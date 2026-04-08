from django.test import Client, SimpleTestCase, override_settings


@override_settings(ROOT_URLCONF="hotel_management.test_urls")
class CustomErrorPageMiddlewareTests(SimpleTestCase):
    def setUp(self):
        self.client = Client(raise_request_exception=False)

    def test_404_template_is_used_for_missing_route(self):
        response = self.client.get("/missing-page/")

        self.assertEqual(response.status_code, 404)
        self.assertTemplateUsed(response, "404.html")

    def test_400_template_is_used_for_suspicious_operation(self):
        response = self.client.get("/test-400/")

        self.assertEqual(response.status_code, 400)
        self.assertTemplateUsed(response, "400.html")

    def test_403_template_is_used_for_permission_denied(self):
        response = self.client.get("/test-403/")

        self.assertEqual(response.status_code, 403)
        self.assertTemplateUsed(response, "403.html")

    def test_404_template_is_used_for_plain_404_response(self):
        response = self.client.get("/test-404-response/")

        self.assertEqual(response.status_code, 404)
        self.assertTemplateUsed(response, "404.html")

    def test_500_template_is_used_for_unhandled_exception(self):
        response = self.client.get("/test-500/")

        self.assertEqual(response.status_code, 500)
        self.assertTemplateUsed(response, "500.html")
