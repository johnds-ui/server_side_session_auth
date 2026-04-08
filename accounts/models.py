import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models


class Restaurant(models.Model):
    """
    Each restaurant is its own isolated tenant.
    All menu items, categories, orders and staff belong to exactly one restaurant.
    `flask_tenant_id` links to `auth_tenants.id` in the Flask auth DB.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True)
    address = models.TextField(blank=True)
    phone = models.CharField(max_length=30, blank=True)
    is_active = models.BooleanField(default=True)
    flask_tenant_id = models.UUIDField(unique=True, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ["name"]


class User(AbstractUser):
    """
    Thin Django user record.  Passwords are managed by the Flask auth service.

    Roles:
        customer         — browse menu, place own orders
        waiter           — manage orders for their restaurant
        restaurant_admin — full control of their restaurant (menu, orders, staff)
    """
    ROLE_CHOICES = [
        ("customer", "Customer"),
        ("waiter", "Waiter"),
        ("restaurant_admin", "Restaurant Admin"),
    ]

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="customer")
    restaurant = models.ForeignKey(
        Restaurant,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="staff",
    )

    def is_restaurant_admin(self):
        return self.role == "restaurant_admin"

    def is_waiter(self):
        return self.role == "waiter"

    def is_staff_of(self, restaurant_pk):
        return str(self.restaurant_id) == str(restaurant_pk)

    class Meta:
        verbose_name = "user"
        verbose_name_plural = "users"
