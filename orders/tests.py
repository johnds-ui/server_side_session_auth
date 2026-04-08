from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from menu.models import Category, MenuItem
from orders.models import Cart, CartItem, Order, OrderItem


@override_settings(ROOT_URLCONF="hotel_management.urls")
class OrderExperienceTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(
            username="guest",
            password="password123",
            role="user",
        )
        self.client.force_login(self.user)

        category = Category.objects.create(name="Main Course")
        self.menu_item = MenuItem.objects.create(
            category=category,
            name="Paneer Butter Masala",
            price=Decimal("249.00"),
        )

    def _create_order(self, status):
        order = Order.objects.create(user=self.user, status=status)
        OrderItem.objects.create(
            order=order,
            menu_item=self.menu_item,
            quantity=2,
            price=self.menu_item.price,
        )
        return order

    def test_order_history_groups_orders_by_status(self):
        self._create_order("pending")
        self._create_order("completed")
        self._create_order("cancelled")

        response = self.client.get(reverse("orders:order_history"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Active Orders")
        self.assertContains(response, "Completed Orders")
        self.assertContains(response, "Cancelled Orders")
        self.assertEqual(len(response.context["active_orders"]), 1)
        self.assertEqual(len(response.context["completed_orders"]), 1)
        self.assertEqual(len(response.context["cancelled_orders"]), 1)

    def test_order_tracking_page_renders_refresh_and_summary(self):
        order = self._create_order("out_for_delivery")

        response = self.client.get(reverse("orders:order_track", args=[order.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'http-equiv="refresh"', html=False)
        self.assertContains(response, "Tracking Timeline")
        self.assertContains(response, "Paneer Butter Masala")

    def test_active_order_can_be_cancelled(self):
        order = self._create_order("pending")

        response = self.client.post(reverse("orders:order_cancel", args=[order.id]))

        self.assertRedirects(response, reverse("orders:order_history"))
        order.refresh_from_db()
        self.assertEqual(order.status, "cancelled")

    def test_completed_order_can_be_reordered_into_cart(self):
        order = self._create_order("completed")

        response = self.client.post(reverse("orders:order_reorder", args=[order.id]))

        self.assertRedirects(response, reverse("orders:cart_detail"))
        cart = Cart.objects.get(user=self.user)
        cart_item = CartItem.objects.get(cart=cart, menu_item=self.menu_item)
        self.assertEqual(cart_item.quantity, 2)

    def test_add_to_cart_returns_to_menu_with_preview_card(self):
        response = self.client.post(
            reverse("menu:add_to_cart", args=[self.menu_item.id]),
            {"quantity": 1, "next": reverse("menu:menu_list")},
            follow=True,
        )

        self.assertRedirects(response, reverse("menu:menu_list"))
        self.assertContains(response, "Added to cart")
        self.assertContains(response, "View Cart")
        cart = Cart.objects.get(user=self.user)
        cart_item = CartItem.objects.get(cart=cart, menu_item=self.menu_item)
        self.assertEqual(cart_item.quantity, 1)

    def test_add_to_cart_detail_page_keeps_user_on_detail_page(self):
        response = self.client.post(
            reverse("menu:add_to_cart", args=[self.menu_item.id]),
            {"quantity": 2, "next": reverse("menu:menu_detail", args=[self.menu_item.id])},
            follow=True,
        )

        self.assertRedirects(response, reverse("menu:menu_detail", args=[self.menu_item.id]))
        self.assertContains(response, "Paneer Butter Masala")
        self.assertContains(response, "View Cart")
