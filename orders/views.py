from django.contrib import messages
from django.db.models import Prefetch
from django.db import transaction
from django.shortcuts import render, redirect, get_object_or_404

from .models import Cart, CartItem, Order, OrderItem
from .forms import CartAddForm, OrderCreateForm
from hotel_management.flask_auth_utils import (
    flask_login_required,
    flask_fresh_required,
    flask_waiter_or_admin_required,
    restaurant_abac_check,
)


ACTIVE_STATUSES = {"pending", "preparing", "out_for_delivery"}
COMPLETED_STATUSES = {"served", "completed"}
TIMELINE_STEPS = [
    ("pending", "Order Confirmed"),
    ("preparing", "Preparing"),
    ("ready", "Ready"),
    ("picked_up", "Picked Up"),
    ("out_for_delivery", "On the Way"),
    ("delivered", "Delivered"),
]
STATUS_STEP_INDEX = {
    "pending": 0,
    "preparing": 1,
    "out_for_delivery": 4,
    "served": 5,
    "completed": 5,
    "cancelled": 0,
}
STATUS_NOTES = {
    "pending": "Your order is confirmed and waiting for the kitchen team to begin.",
    "preparing": "Your meal is in the kitchen now and moving through preparation.",
    "out_for_delivery": "Your order is on the way and should arrive shortly.",
    "served": "Your order has arrived. We hope you enjoy every bite.",
    "completed": "This order is complete. You can re-order it anytime.",
    "cancelled": "This order has been cancelled. Reach out if you need help placing it again.",
}


def _get_restaurant(request):
    """Return Restaurant from tenant_id in Flask session, or None."""
    from accounts.models import Restaurant
    tid = request.flask_session.get("tenant_id")
    if not tid:
        return None
    return Restaurant.objects.filter(flask_tenant_id=tid).first()


def _require_customer(request):
    """Redirect staff away from customer-only flows."""
    role = request.flask_session.get("role")
    if role in ("restaurant_admin", "waiter"):
        messages.info(request, "Staff accounts use the admin panel for order operations.")
        return redirect("accounts:admin_dashboard")
    if not request.user.is_authenticated:
        return redirect("accounts:login")
    return None


def _get_selected_restaurant(request):
    """
    Return (restaurant, None) from the session-selected restaurant.
    Return (None, redirect_response) when selection is missing or invalid.
    """
    from accounts.models import Restaurant
    selected_id = request.session.get("selected_restaurant_id")
    if not selected_id:
        messages.warning(request, "Please select a restaurant first.")
        return None, redirect("accounts:restaurant_select")
    restaurant = Restaurant.objects.filter(pk=selected_id, is_active=True).first()
    if not restaurant:
        request.session.pop("selected_restaurant_id", None)
        messages.warning(request, "Your selected restaurant is no longer available.")
        return None, redirect("accounts:restaurant_select")
    return restaurant, None


def _orders_for_user(user):
    return (
        Order.objects.filter(user=user)
        .prefetch_related(
            Prefetch(
                "order_items",
                queryset=OrderItem.objects.select_related("menu_item").order_by("id"),
            )
        )
        .order_by("-created_at")
    )


def _decorate_order(order):
    order_items = list(order.order_items.all())
    primary_item = order_items[0] if order_items else None
    item_names = [item.menu_item.name for item in order_items]

    order.primary_item = primary_item
    order.primary_image_url = (
        primary_item.menu_item.image.url
        if primary_item and primary_item.menu_item.image
        else None
    )
    order.item_names = item_names
    order.item_summary = ", ".join(item_names[:3])
    if len(item_names) > 3:
        order.item_summary = f"{order.item_summary} +{len(item_names) - 3} more"
    if not item_names:
        order.item_summary = "No items available"

    order.item_count = sum(item.quantity for item in order_items)
    order.total_amount = order.total()
    order.is_active = order.status in ACTIVE_STATUSES
    order.is_completed = order.status in COMPLETED_STATUSES
    order.is_cancelled = order.status == "cancelled"
    order.current_step_index = STATUS_STEP_INDEX.get(order.status, 0)
    order.live_status_note = STATUS_NOTES.get(
        order.status, "We will keep your order status updated here."
    )

    timeline_steps = []
    for index, (code, label) in enumerate(TIMELINE_STEPS):
        is_done = index <= order.current_step_index and not order.is_cancelled
        timestamp = order.created_at if index == 0 else None
        timeline_steps.append(
            {
                "code": code,
                "label": label,
                "is_done": is_done,
                "is_current": index == order.current_step_index and not order.is_cancelled,
                "timestamp": timestamp,
            }
        )
    order.timeline_steps = timeline_steps
    return order


@flask_login_required
def cart_detail(request):
    block = _require_customer(request)
    if block:
        return block
    restaurant, err = _get_selected_restaurant(request)
    if err:
        return err
    cart, _ = Cart.objects.get_or_create(user=request.user, restaurant=restaurant)
    return render(request, "orders/cart_detail.html", {"cart": cart})


@flask_login_required
def cart_remove(request, pk):
    block = _require_customer(request)
    if block:
        return block
    restaurant, err = _get_selected_restaurant(request)
    if err:
        return err
    cart = get_object_or_404(Cart, user=request.user, restaurant=restaurant)
    cart_item = get_object_or_404(CartItem, cart=cart, pk=pk)
    cart_item.delete()
    messages.info(request, "Item removed from cart.")
    return redirect("orders:cart_detail")


@flask_login_required
def cart_update(request, pk):
    block = _require_customer(request)
    if block:
        return block
    restaurant, err = _get_selected_restaurant(request)
    if err:
        return err
    cart = get_object_or_404(Cart, user=request.user, restaurant=restaurant)
    cart_item = get_object_or_404(CartItem, cart=cart, pk=pk)
    form = CartAddForm(request.POST)
    if form.is_valid():
        cart_item.quantity = form.cleaned_data["quantity"]
        cart_item.save()
        messages.success(request, "Cart updated.")
    return redirect("orders:cart_detail")


@flask_login_required
def order_create(request):
    block = _require_customer(request)
    if block:
        return block
    restaurant, err = _get_selected_restaurant(request)
    if err:
        return err
    cart = get_object_or_404(Cart, user=request.user, restaurant=restaurant)
    # Hard ABAC guard: cart.restaurant must match session restaurant
    if cart.restaurant_id != restaurant.pk:
        messages.error(request, "Cart / restaurant mismatch. Please try again.")
        return redirect("accounts:restaurant_select")
    if cart.items.count() == 0:
        messages.warning(request, "Your cart is empty.")
        return redirect("menu:menu_list")
    if request.method == "POST":
        form = OrderCreateForm(request.POST)
        if form.is_valid():
            with transaction.atomic():
                Order.objects.filter(cart=cart).update(cart=None)
                order = form.save(commit=False)
                order.user = request.user
                order.cart = cart
                order.restaurant = restaurant  # always from session, not from cart
                order.save()
                for item in cart.items.all():
                    OrderItem.objects.create(
                        order=order,
                        menu_item=item.menu_item,
                        quantity=item.quantity,
                        price=item.menu_item.price,
                    )
                cart.items.all().delete()
            messages.success(request, "Order placed successfully.")
            return redirect("orders:order_history")
    else:
        form = OrderCreateForm()
    return render(request, "orders/order_create.html", {"form": form, "cart": cart})


@flask_login_required
def order_history(request):
    block = _require_customer(request)
    if block:
        return block
    orders = [_decorate_order(order) for order in _orders_for_user(request.user)]
    active_orders = [o for o in orders if o.is_active]
    completed_orders = [o for o in orders if o.is_completed]
    cancelled_orders = [o for o in orders if o.is_cancelled]
    return render(request, "orders/order_history.html", {
        "orders": orders,
        "active_orders": active_orders,
        "completed_orders": completed_orders,
        "cancelled_orders": cancelled_orders,
    })


@flask_login_required
def order_track(request, pk):
    block = _require_customer(request)
    if block:
        return block
    order = get_object_or_404(_orders_for_user(request.user), pk=pk)
    return render(request, "orders/order_track.html", {"order": _decorate_order(order)})


@flask_login_required
def order_cancel(request, pk):
    block = _require_customer(request)
    if block:
        return block
    order = get_object_or_404(Order, pk=pk, user=request.user)
    if request.method != "POST":
        return redirect("orders:order_history")
    if order.status in ACTIVE_STATUSES:
        order.status = "cancelled"
        order.save(update_fields=["status"])
        messages.success(request, f"Order #{order.id} was cancelled.")
    else:
        messages.info(request, "Only active orders can be cancelled.")
    return redirect("orders:order_history")


@flask_login_required
def order_reorder(request, pk):
    block = _require_customer(request)
    if block:
        return block
    order = get_object_or_404(_orders_for_user(request.user), pk=pk)
    if request.method != "POST":
        return redirect("orders:order_history")
    cart, _ = Cart.objects.get_or_create(
        user=request.user,
        restaurant=order.restaurant,
    )
    for order_item in order.order_items.all():
        cart_item, created = CartItem.objects.get_or_create(
            cart=cart,
            menu_item=order_item.menu_item,
            defaults={"quantity": order_item.quantity},
        )
        if not created:
            cart_item.quantity += order_item.quantity
            cart_item.save(update_fields=["quantity"])
    messages.success(request, "Items added back to your cart.")
    return redirect("orders:cart_detail")


# ---------------------------------------------------------------------------
# Staff views — waiter + restaurant_admin (restaurant-scoped)
# ---------------------------------------------------------------------------

def _order_restaurant_pk(request, pk, **_kw):
    order = get_object_or_404(Order, pk=pk)
    return order.restaurant.flask_tenant_id if order.restaurant else None


@flask_waiter_or_admin_required
def admin_order_list(request):
    restaurant = _get_restaurant(request)
    orders = (
        Order.objects
        .filter(restaurant=restaurant)
        .order_by("-created_at")
        if restaurant else Order.objects.none()
    )
    return render(request, "orders/admin_order_list.html", {
        "orders": orders,
        "restaurant": restaurant,
    })


@flask_waiter_or_admin_required
@restaurant_abac_check(_order_restaurant_pk)
def admin_order_update(request, pk):
    order = get_object_or_404(Order, pk=pk)
    status_choices = Order._meta.get_field("status").choices
    role = request.flask_session.get("role")
    # Waiters cannot cancel orders — only admins can
    if role == "waiter":
        status_choices = [
            (code, label)
            for code, label in status_choices
            if code != "cancelled"
        ]
    if request.method == "POST":
        status = request.POST.get("status")
        allowed = dict(status_choices)
        if status in allowed:
            order.status = status
            order.save(update_fields=["status"])
            messages.success(request, "Order status updated.")
            return redirect("orders:admin_order_list")
        else:
            messages.error(request, "Invalid or disallowed status.")
    return render(request, "orders/admin_order_update.html", {
        "order": order,
        "status_choices": list(status_choices),
    })
