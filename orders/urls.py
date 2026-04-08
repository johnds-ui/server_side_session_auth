from django.urls import path
from . import views

app_name = "orders"

urlpatterns = [
    path("cart/", views.cart_detail, name="cart_detail"),
    path("cart/remove/<int:pk>/", views.cart_remove, name="cart_remove"),
    path("cart/update/<int:pk>/", views.cart_update, name="cart_update"),
    path("order/create/", views.order_create, name="order_create"),
    path("order/history/", views.order_history, name="order_history"),
    path("order/<int:pk>/track/", views.order_track, name="order_track"),
    path("order/<int:pk>/cancel/", views.order_cancel, name="order_cancel"),
    path("order/<int:pk>/reorder/", views.order_reorder, name="order_reorder"),

    # admin endpoints
    path("admin/orders/", views.admin_order_list, name="admin_order_list"),
    path("admin/orders/<int:pk>/", views.admin_order_update, name="admin_order_update"),
]
