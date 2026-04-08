from django.conf import settings
from django.db import models
from menu.models import MenuItem


class Cart(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="carts",
    )
    restaurant = models.ForeignKey(
        "accounts.Restaurant",
        on_delete=models.CASCADE,
        null=True,
        related_name="carts",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        # One cart per customer per restaurant — enforced at DB level
        unique_together = [["user", "restaurant"]]

    def __str__(self):
        return f"Cart ({self.user.username} @ {self.restaurant})"

    def total(self):
        return sum(item.subtotal() for item in self.items.all())


class CartItem(models.Model):
    cart = models.ForeignKey(Cart, related_name="items", on_delete=models.CASCADE)
    menu_item = models.ForeignKey(MenuItem, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)

    def __str__(self):
        return f"{self.quantity} x {self.menu_item.name}"

    def subtotal(self):
        return self.menu_item.price * self.quantity


ORDER_STATUS_CHOICES = [
    ("pending", "Pending"),
    ("preparing", "Preparing"),
    ("out_for_delivery", "Out for Delivery"),
    ("served", "Served"),
    ("completed", "Completed"),
    ("cancelled", "Cancelled"),
]


class Order(models.Model):
    restaurant = models.ForeignKey(
        "accounts.Restaurant",
        on_delete=models.CASCADE,
        related_name="orders",
        null=True,
    )
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    cart = models.OneToOneField(Cart, on_delete=models.SET_NULL, null=True)
    status = models.CharField(max_length=20, choices=ORDER_STATUS_CHOICES, default="pending")
    delivery_details = models.TextField(blank=True)
    table_number = models.CharField(max_length=10, blank=True)
    room_number = models.CharField(max_length=10, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Order #{self.id} - {self.user} - {self.status}"

    def total(self):
        order_items_total = sum(item.subtotal() for item in self.order_items.all())
        if order_items_total:
            return order_items_total
        return self.cart.total() if self.cart else 0


class OrderItem(models.Model):
    order = models.ForeignKey(Order, related_name="order_items", on_delete=models.CASCADE)
    menu_item = models.ForeignKey(MenuItem, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)
    price = models.DecimalField(max_digits=8, decimal_places=2)

    def __str__(self):
        return f"{self.quantity} x {self.menu_item.name}"

    def subtotal(self):
        return self.price * self.quantity
