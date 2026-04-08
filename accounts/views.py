"""
accounts/views.py
Authentication is delegated to the Flask auth service.
Admin = restaurant_admin role.
"""
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from hotel_management.flask_auth_utils import (
    call_flask,
    flask_admin_required,
    flask_fresh_required,
    flask_waiter_or_admin_required,
)

from .forms import AddStaffForm, AdminReauthForm, RestaurantAdminRegisterForm, UserAdminUpdateForm, UserLoginForm, UserRegisterForm
from .models import Restaurant, User
from menu.models import MenuItem
from orders.models import Order

_COOKIE = getattr(settings, "FLASK_SESSION_COOKIE_NAME", "auth_session")
_SECURE = not settings.DEBUG


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _set_auth_cookie(response, value: str) -> None:
    response.set_cookie(
        _COOKIE, value=value, httponly=True, secure=_SECURE,
        samesite="Strict", max_age=8 * 3600,
    )


def _clear_auth_cookie(response) -> None:
    response.delete_cookie(_COOKIE, path="/", samesite="Strict")


def _get_user_restaurant(request) -> "Restaurant | None":
    """Return the Restaurant the current staff member belongs to."""
    tid = request.flask_session.get("tenant_id")
    if not tid:
        return None
    return Restaurant.objects.filter(flask_tenant_id=tid).first()


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------

def register_view(request):
    if request.flask_session.get("role"):
        return redirect("menu:menu_list")

    if request.method == "POST":
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            resp, err = call_flask("POST", "/auth/register", json={
                "email": form.cleaned_data["email"],
                "password": form.cleaned_data["password1"],
            })
            if err:
                messages.error(request, err)
            elif resp.status_code == 201:
                messages.success(request, "Account created. Please log in.")
                return redirect("accounts:login")
            else:
                form.add_error(None, resp.json().get("error", "Registration failed."))
    else:
        form = UserRegisterForm()
    return render(request, "accounts/register.html", {"form": form})


# ---------------------------------------------------------------------------
# Restaurant picker (customer must select a restaurant before ordering)
# ---------------------------------------------------------------------------

def restaurant_select_view(request):
    """
    Shows all active restaurants. Any visitor (guest or customer) picks one;
    selection stored in session. Staff are redirected straight to the dashboard.
    """
    role = request.flask_session.get("role")
    if role in _STAFF_ROLES:
        return redirect("accounts:admin_dashboard")

    if request.method == "POST":
        pk = request.POST.get("restaurant_id")
        restaurant = Restaurant.objects.filter(pk=pk, is_active=True).first()
        if restaurant:
            old_id = request.session.get("selected_restaurant_id")
            if old_id and old_id != str(restaurant.pk):
                # Notify the user; their old cart is preserved in the DB for each restaurant
                messages.info(
                    request,
                    f"Switched to {restaurant.name}. "
                    "Your previous cart is saved and will return when you switch back.",
                )
            request.session["selected_restaurant_id"] = str(restaurant.pk)
            request.session["selected_restaurant_name"] = restaurant.name
            return redirect("menu:menu_list")
        messages.error(request, "Restaurant not found.")

    restaurants = Restaurant.objects.filter(is_active=True).order_by("name")
    current_id = request.session.get("selected_restaurant_id")
    return render(request, "accounts/restaurant_select.html", {
        "restaurants": restaurants,
        "current_id": current_id,
    })


# ---------------------------------------------------------------------------
# Login (customer)
# ---------------------------------------------------------------------------

def login_view(request):
    if request.flask_session.get("role"):
        return redirect("menu:menu_list")

    if request.method == "POST":
        form = UserLoginForm(request.POST)
        if form.is_valid():
            resp, err = call_flask("POST", "/auth/login", json={
                "email": form.cleaned_data["email"],
                "password": form.cleaned_data["password"],
            })
            if err:
                messages.error(request, err)
            elif resp.status_code == 200:
                data = resp.json()
                sid = resp.cookies.get(_COOKIE)
                if not sid:
                    messages.error(request, "Login failed — no session returned.")
                    return render(request, "accounts/login.html", {"form": form})
                # Cycle the Django session key on login to prevent session fixation:
                # any pre-login session ID the attacker may have planted is now invalid.
                request.session.cycle_key()
                request.session["flask_csrf_token"] = data.get("csrf_token", "")
                # Customers must pick a restaurant unless they already have one selected
                if not request.session.get("selected_restaurant_id"):
                    response = redirect("accounts:restaurant_select")
                else:
                    response = redirect("menu:menu_list")
                _set_auth_cookie(response, sid)
                messages.success(request, "Logged in successfully.")
                return response
            else:
                form.add_error(None, resp.json().get("error", "Invalid credentials."))
    else:
        form = UserLoginForm()
    return render(request, "accounts/login.html", {"form": form})


# ---------------------------------------------------------------------------
# Admin / Staff login
# ---------------------------------------------------------------------------

_STAFF_ROLES = {"restaurant_admin", "waiter"}


def admin_login_view(request):
    if request.flask_session.get("role") in _STAFF_ROLES:
        return redirect("accounts:admin_dashboard")

    if request.method == "POST":
        form = UserLoginForm(request.POST)
        if form.is_valid():
            resp, err = call_flask("POST", "/auth/login", json={
                "email": form.cleaned_data["email"],
                "password": form.cleaned_data["password"],
            })
            if err:
                messages.error(request, err)
            elif resp.status_code == 200:
                data = resp.json()
                role = data.get("user", {}).get("role", "")
                if role not in _STAFF_ROLES:
                    messages.error(request, "Staff access only. Use the customer login for orders.")
                    return render(request, "accounts/admin_login.html", {"form": form})

                sid = resp.cookies.get(_COOKIE)
                if not sid:
                    messages.error(request, "Login failed — no session returned.")
                    return render(request, "accounts/admin_login.html", {"form": form})

                # Cycle Django session key to prevent session fixation
                request.session.cycle_key()
                request.session["flask_csrf_token"] = data.get("csrf_token", "")
                response = redirect("accounts:admin_dashboard")
                _set_auth_cookie(response, sid)
                messages.success(request, "Logged in successfully.")
                return response
            else:
                form.add_error(None, resp.json().get("error", "Invalid credentials."))
    else:
        form = UserLoginForm()
    return render(request, "accounts/admin_login.html", {"form": form})


# ---------------------------------------------------------------------------
# Restaurant admin — self-registration (temporary convenience route)
# Remove this view + URL once initial admin accounts are provisioned.
# ---------------------------------------------------------------------------

def admin_register_view(request):
    """
    Lets anyone register a NEW restaurant-admin account in one step.
    Creates a Restaurant record and a restaurant_admin user via Flask.
    INTENDED FOR INITIAL SETUP ONLY — disable once provisioned.
    """
    # Already logged-in staff go straight to dashboard
    if request.flask_session.get("role") in _STAFF_ROLES:
        return redirect("accounts:admin_dashboard")

    if request.method == "POST":
        form = RestaurantAdminRegisterForm(request.POST)
        if form.is_valid():
            # Step 1 — register admin user in Flask (role=restaurant_admin)
            resp, err = call_flask("POST", "/auth/register", json={
                "email": form.cleaned_data["email"],
                "password": form.cleaned_data["password1"],
                "role": "restaurant_admin",
            })
            if err:
                messages.error(request, err)
            elif resp.status_code == 201:
                flask_user = resp.json().get("user", {})
                tenant_id = flask_user.get("tenant_id")

                # Step 2 — create the matching Restaurant row in Django DB
                restaurant_name = form.cleaned_data["restaurant_name"]
                if tenant_id:
                    import uuid
                    Restaurant.objects.get_or_create(
                        flask_tenant_id=tenant_id,
                        defaults={"name": restaurant_name},
                    )
                else:
                    # Flask didn't assign a tenant yet — create restaurant and
                    # link via a second PATCH call if your Flask service supports it,
                    # or handle manually. For now just create the restaurant.
                    new_restaurant = Restaurant.objects.create(
                        name=restaurant_name,
                        flask_tenant_id=uuid.uuid4(),
                    )

                messages.success(
                    request,
                    f'Restaurant admin account created for "{restaurant_name}". '
                    "You can now log in below.",
                )
                return redirect("accounts:admin_login")
            else:
                error = resp.json().get("error", "Registration failed.")
                form.add_error(None, error)
    else:
        form = RestaurantAdminRegisterForm()

    return render(request, "accounts/admin_register.html", {"form": form})


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

def logout_view(request):
    # Invalidate the server-side Flask session first
    call_flask("POST", "/auth/logout", request=request)
    # Add message before flushing (middleware will save it to the new session)
    messages.info(request, "You have been logged out.")
    # Flush the Django session: deletes all session data AND rotates the session key.
    # This prevents session fixation — an attacker who obtained the old session cookie
    # cannot reuse it because the key no longer exists server-side.
    request.session.flush()
    response = redirect("accounts:login")
    _clear_auth_cookie(response)
    return response


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------

@login_required
def profile_view(request):
    return render(request, "accounts/profile.html")


# ---------------------------------------------------------------------------
# Re-authentication gate
# ---------------------------------------------------------------------------

def admin_reauth_view(request):
    if not request.flask_session.get("role"):
        return redirect("accounts:admin_login")

    if request.method == "POST":
        form = AdminReauthForm(request.POST)
        if form.is_valid():
            resp, err = call_flask("POST", "/auth/reauth", request=request,
                                   json={"password": form.cleaned_data["password"]})
            if err:
                messages.error(request, err)
            elif resp.status_code == 200:
                messages.success(request, "Identity confirmed.")
                next_url = request.session.pop("reauth_next", None)
                return redirect(next_url or "accounts:admin_dashboard")
            else:
                data = resp.json()
                if data.get("session_terminated"):
                    # Wrong password — Flask killed the session server-side.
                    # Flush the Django session (cycles the session ID to prevent
                    # session fixation) and force a full re-login.
                    messages.error(
                        request,
                        "Session ended — incorrect password entered during security "
                        "check. Please log in again.",
                    )
                    request.session.flush()
                    response = redirect("accounts:admin_login")
                    _clear_auth_cookie(response)
                    return response
                form.add_error(None, data.get("error", "Password incorrect."))
    else:
        form = AdminReauthForm()
    return render(request, "accounts/admin_reauth.html", {"form": form})


# ---------------------------------------------------------------------------
# Admin dashboard
# ---------------------------------------------------------------------------

@flask_waiter_or_admin_required
def admin_dashboard_view(request):
    restaurant = _get_user_restaurant(request)
    role = request.flask_session.get("role")
    base_qs = Order.objects.filter(restaurant=restaurant) if restaurant else Order.objects.none()
    context = {
        "restaurant": restaurant,
        "role": role,
        "users_count": User.objects.filter(restaurant=restaurant).count() if restaurant else 0,
        "menu_items_count": MenuItem.objects.filter(restaurant=restaurant).count() if restaurant else 0,
        "orders_count": base_qs.count(),
        "pending_orders_count": base_qs.filter(status="pending").count(),
    }
    return render(request, "accounts/admin_dashboard.html", context)


# ---------------------------------------------------------------------------
# Staff management  (restaurant_admin only)
# ---------------------------------------------------------------------------

@flask_admin_required
def admin_user_list_view(request):
    restaurant = _get_user_restaurant(request)
    users = User.objects.filter(restaurant=restaurant).order_by("role", "email") if restaurant else User.objects.none()
    return render(request, "accounts/admin_user_list.html", {
        "users": users,
        "restaurant": restaurant,
    })


@flask_admin_required
@flask_fresh_required
def admin_user_update_view(request, pk):
    restaurant = _get_user_restaurant(request)
    # ABAC: only users in the admin's restaurant
    user_obj = get_object_or_404(User, pk=pk, restaurant=restaurant)

    if request.method == "POST":
        form = UserAdminUpdateForm(request.POST)
        if form.is_valid():
            user_obj.email = form.cleaned_data["email"]
            user_obj.role = form.cleaned_data["role"]
            user_obj.is_active = form.cleaned_data["is_active"]
            user_obj.save(update_fields=["email", "role", "is_active"])
            messages.success(request, "User updated successfully.")
            return redirect("accounts:admin_user_list")
    else:
        form = UserAdminUpdateForm(initial={
            "email": user_obj.email,
            "role": user_obj.role,
            "is_active": user_obj.is_active,
        })
    return render(request, "accounts/admin_user_update.html", {
        "form": form, "user_obj": user_obj, "restaurant": restaurant,
    })


@flask_admin_required
@flask_fresh_required
def admin_user_delete_view(request, pk):
    restaurant = _get_user_restaurant(request)
    user_obj = get_object_or_404(User, pk=pk, restaurant=restaurant)
    if request.method == "POST":
        if user_obj == request.user:
            messages.error(request, "You cannot delete your own account.")
        else:
            user_obj.delete()
            messages.success(request, "User removed from restaurant.")
    return redirect("accounts:admin_user_list")


# ---------------------------------------------------------------------------
# Add staff  (restaurant_admin only — invites a new waiter to their restaurant)
# ---------------------------------------------------------------------------

@flask_admin_required
@flask_fresh_required
def admin_add_staff_view(request):
    restaurant = _get_user_restaurant(request)
    if not restaurant:
        messages.error(request, "Your account is not linked to a restaurant.")
        return redirect("accounts:admin_dashboard")

    if request.method == "POST":
        form = AddStaffForm(request.POST)
        if form.is_valid():
            # Register in Flask with the admin's tenant_id so the new user is
            # placed inside the same restaurant automatically.
            resp, err = call_flask("POST", "/auth/register", json={
                "email": form.cleaned_data["email"],
                "password": form.cleaned_data["password"],
                "role": form.cleaned_data["role"],
                "tenant_id": str(restaurant.flask_tenant_id),
            }, request=request)
            if err:
                messages.error(request, err)
            elif resp.status_code == 201:
                flask_user = resp.json().get("user", {})
                # Mirror the new user in Django so admin_user_list shows them
                User.objects.get_or_create(
                    username=form.cleaned_data["email"],
                    defaults={
                        "email": form.cleaned_data["email"],
                        "role": form.cleaned_data["role"],
                        "restaurant": restaurant,
                        "is_active": True,
                    },
                )
                messages.success(request, f"Staff member added: {form.cleaned_data['email']}")
                return redirect("accounts:admin_user_list")
            else:
                form.add_error(None, resp.json().get("error", "Could not add staff member."))
    else:
        form = AddStaffForm()

    return render(request, "accounts/admin_add_staff.html", {
        "form": form,
        "restaurant": restaurant,
    })


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------

def password_reset_view(request):
    messages.info(request, "Password reset is managed by the auth service. Please contact your restaurant admin.")
    return redirect("accounts:login")

