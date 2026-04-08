from django.urls import path
from . import views

app_name = "menu"

urlpatterns = [
    path("", views.menu_list, name="menu_list"),
    path("item/<int:pk>/", views.menu_detail, name="menu_detail"),
    path("item/<int:pk>/add-to-cart/", views.add_to_cart, name="add_to_cart"),
    path("admin/categories/", views.admin_category_list, name="admin_category_list"),
    path("admin/categories/create/", views.admin_category_create, name="admin_category_create"),
    path("admin/categories/<int:pk>/edit/", views.admin_category_update, name="admin_category_update"),
    path("admin/categories/<int:pk>/delete/", views.admin_category_delete, name="admin_category_delete"),
    path("admin/items/", views.admin_menu_list, name="admin_menu_list"),
    path("admin/items/create/", views.admin_menu_create, name="admin_menu_create"),
    path("admin/items/<int:pk>/edit/", views.admin_menu_update, name="admin_menu_update"),
    path("admin/items/<int:pk>/delete/", views.admin_menu_delete, name="admin_menu_delete"),
]
