from urllib.parse import urlsplit

from django.contrib import messages
from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse
from .models import MenuItem, Category
from .forms import MenuItemAdminForm, CategoryAdminForm
from orders.forms import CartAddForm
from orders.models import Cart, CartItem
from hotel_management.flask_auth_utils import (
    flask_admin_required,
    flask_fresh_required,
    flask_waiter_or_admin_required,
    restaurant_abac_check,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_restaurant(request):
    """Return Restaurant from tenant_id in Flask session, or None."""
    from accounts.models import Restaurant
    tid = request.flask_session.get("tenant_id")
    if not tid:
        return None
    return Restaurant.objects.filter(flask_tenant_id=tid).first()


def _consume_cart_preview(request):
    preview = request.session.pop("cart_preview", None)
    role = request.flask_session.get("role")
    if not preview or not request.user.is_authenticated or role in ("restaurant_admin", "waiter"):
        return None
    cart = Cart.objects.filter(user=request.user).first()
    if not cart:
        return None
    recent_items = list(cart.items.select_related("menu_item").order_by("-id")[:4])
    avatar_items = [
        {
            "name": ci.menu_item.name,
            "image_url": ci.menu_item.image.url if ci.menu_item.image else None,
        }
        for ci in recent_items
    ]
    preview["avatar_items"] = avatar_items
    preview["cart_count"] = cart.items.count()
    preview["cart_total"] = cart.total()
    return preview


def _get_add_to_cart_redirect(request):
    next_url = request.POST.get("next")
    if next_url and next_url.startswith("/"):
        return next_url
    referer = request.META.get("HTTP_REFERER", "")
    if referer:
        parsed = urlsplit(referer)
        path = parsed.path or ""
        if path.startswith("/menu/"):
            return f"{path}?{parsed.query}" if parsed.query else path
    return reverse("menu:menu_list")


# ---------------------------------------------------------------------------
# Public menu — all items visible (no restaurant filter for public browsing)
# ---------------------------------------------------------------------------

def menu_list(request):
    from accounts.models import Restaurant
    role = request.flask_session.get("role")
    tid = request.flask_session.get("tenant_id")

    if role in ("restaurant_admin", "waiter") and tid:
        # Staff: show their own restaurant's menu
        restaurant = Restaurant.objects.filter(flask_tenant_id=tid).first()
        categories = Category.objects.filter(restaurant=restaurant).prefetch_related("items") if restaurant else Category.objects.none()
        selected_restaurant = restaurant
    else:
        # Guest and customer: honour session-selected restaurant; redirect to picker if none
        selected_id = request.session.get("selected_restaurant_id")
        if not selected_id:
            return redirect("accounts:restaurant_select")
        restaurant = Restaurant.objects.filter(pk=selected_id, is_active=True).first()
        if not restaurant:
            request.session.pop("selected_restaurant_id", None)
            return redirect("accounts:restaurant_select")
        categories = Category.objects.filter(restaurant=restaurant).prefetch_related("items")
        selected_restaurant = restaurant

    return render(request, "menu/menu_list.html", {
        "categories": categories,
        "cart_preview": _consume_cart_preview(request),
        "selected_restaurant": selected_restaurant,
    })


def menu_detail(request, pk):
    item = get_object_or_404(MenuItem, pk=pk, available=True)
    form = CartAddForm()
    role = request.flask_session.get("role")
    can_order = request.user.is_authenticated and role == "customer"
    return render(request, "menu/menu_detail.html", {
        "item": item,
        "form": form,
        "can_order": can_order,
        "cart_preview": _consume_cart_preview(request),
    })


def add_to_cart(request, pk):
    role = request.flask_session.get("role")
    if not request.user.is_authenticated or role != "customer":
        messages.info(request, "Only customers can add items to cart.")
        return redirect("menu:menu_list")

    item = get_object_or_404(MenuItem, pk=pk, available=True)

    # Enforce: cart items must be from the customer's selected restaurant
    selected_id = request.session.get("selected_restaurant_id")
    if not selected_id or str(item.restaurant_id) != str(selected_id):
        messages.error(request, "This item is not available at your selected restaurant.")
        return redirect("menu:menu_list")

    cart, _ = Cart.objects.get_or_create(
        user=request.user,
        restaurant=item.restaurant,
    )
    form = CartAddForm(request.POST)
    if form.is_valid():
        quantity = form.cleaned_data["quantity"]
        cart_item, created = CartItem.objects.get_or_create(cart=cart, menu_item=item)
        if created:
            cart_item.quantity = quantity
        else:
            cart_item.quantity += quantity
        cart_item.save()
        request.session["cart_preview"] = {
            "item_name": item.name,
            "quantity_added": quantity,
            "item_image_url": item.image.url if item.image else None,
        }
    return redirect(_get_add_to_cart_redirect(request))


# ---------------------------------------------------------------------------
# Admin menu management — restaurant-scoped ABAC
# ---------------------------------------------------------------------------

def _item_restaurant_pk(request, pk, **_kw):
    item = get_object_or_404(MenuItem, pk=pk)
    return item.restaurant.flask_tenant_id if item.restaurant else None


def _cat_restaurant_pk(request, pk, **_kw):
    cat = get_object_or_404(Category, pk=pk)
    return cat.restaurant.flask_tenant_id if cat.restaurant else None


@flask_admin_required
def admin_menu_list(request):
    restaurant = _get_restaurant(request)
    items = (
        MenuItem.objects.filter(restaurant=restaurant)
        .select_related("category")
        .order_by("category__name", "name")
        if restaurant else MenuItem.objects.none()
    )
    return render(request, "menu/admin_menu_list.html", {
        "items": items, "restaurant": restaurant,
    })


@flask_admin_required
def admin_menu_create(request):
    restaurant = _get_restaurant(request)
    if request.method == "POST":
        form = MenuItemAdminForm(request.POST, request.FILES, restaurant=restaurant)
        if form.is_valid():
            item = form.save(commit=False)
            item.restaurant = restaurant
            item.save()
            messages.success(request, "Menu item created.")
            return redirect("menu:admin_menu_list")
    else:
        form = MenuItemAdminForm(restaurant=restaurant)
    return render(request, "menu/admin_menu_form.html", {
        "form": form,
        "page_title": "Create Menu Item",
        "has_categories": Category.objects.filter(restaurant=restaurant).exists(),
    })


@flask_admin_required
@restaurant_abac_check(_item_restaurant_pk)
def admin_menu_update(request, pk):
    restaurant = _get_restaurant(request)
    item = get_object_or_404(MenuItem, pk=pk)
    if request.method == "POST":
        form = MenuItemAdminForm(request.POST, request.FILES, instance=item, restaurant=restaurant)
        if form.is_valid():
            form.save()
            messages.success(request, "Menu item updated.")
            return redirect("menu:admin_menu_list")
    else:
        form = MenuItemAdminForm(instance=item, restaurant=restaurant)
    return render(request, "menu/admin_menu_form.html", {
        "form": form,
        "page_title": f"Edit {item.name}",
        "has_categories": True,
    })


@flask_admin_required
@flask_fresh_required
@restaurant_abac_check(_item_restaurant_pk)
def admin_menu_delete(request, pk):
    item = get_object_or_404(MenuItem, pk=pk)
    if request.method == "POST":
        item.delete()
        messages.success(request, "Menu item deleted.")
    return redirect("menu:admin_menu_list")


@flask_admin_required
def admin_category_list(request):
    restaurant = _get_restaurant(request)
    categories = (
        Category.objects.filter(restaurant=restaurant).order_by("name")
        if restaurant else Category.objects.none()
    )
    return render(request, "menu/admin_category_list.html", {
        "categories": categories, "restaurant": restaurant,
    })


@flask_admin_required
def admin_category_create(request):
    restaurant = _get_restaurant(request)
    if request.method == "POST":
        form = CategoryAdminForm(request.POST)
        if form.is_valid():
            cat = form.save(commit=False)
            cat.restaurant = restaurant
            cat.save()
            messages.success(request, "Category created.")
            return redirect("menu:admin_category_list")
    else:
        form = CategoryAdminForm()
    return render(request, "menu/admin_category_form.html", {
        "form": form, "page_title": "Create Category",
    })


@flask_admin_required
@restaurant_abac_check(_cat_restaurant_pk)
def admin_category_update(request, pk):
    category = get_object_or_404(Category, pk=pk)
    if request.method == "POST":
        form = CategoryAdminForm(request.POST, instance=category)
        if form.is_valid():
            form.save()
            messages.success(request, "Category updated.")
            return redirect("menu:admin_category_list")
    else:
        form = CategoryAdminForm(instance=category)
    return render(request, "menu/admin_category_form.html", {
        "form": form, "page_title": f"Edit {category.name}",
    })


@flask_admin_required
@flask_fresh_required
@restaurant_abac_check(_cat_restaurant_pk)
def admin_category_delete(request, pk):
    category = get_object_or_404(Category, pk=pk)
    if request.method == "POST":
        category.delete()
        messages.success(request, "Category deleted.")
    return redirect("menu:admin_category_list")
