from django.urls import path
from . import views

app_name = "accounts"

urlpatterns = [
    # Restaurant picker (customers choose a restaurant first)
    path("", views.restaurant_select_view, name="restaurant_select"),

    # Auth (proxied to Flask)
    path("register/", views.register_view, name="register"),
    path("login/", views.login_view, name="login"),
    path("admin-login/", views.admin_login_view, name="admin_login"),
    path("admin-register/", views.admin_register_view, name="admin_register"),  # TODO: remove after setup
    path("logout/", views.logout_view, name="logout"),
    path("password-reset/", views.password_reset_view, name="password_reset"),

    # Profile
    path("profile/", views.profile_view, name="profile"),

    # Admin — re-authentication gate
    path("admin/reauth/", views.admin_reauth_view, name="admin_reauth"),

    # Admin — dashboard & user management
    path("admin/dashboard/", views.admin_dashboard_view, name="admin_dashboard"),
    path("admin/users/", views.admin_user_list_view, name="admin_user_list"),
    path("admin/users/add-staff/", views.admin_add_staff_view, name="admin_add_staff"),
    path("admin/users/<int:pk>/edit/", views.admin_user_update_view, name="admin_user_update"),
    path("admin/users/<int:pk>/delete/", views.admin_user_delete_view, name="admin_user_delete"),
]
