from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("accounts.urls")),
    path("menu/", include("menu.urls")),
    path("orders/", include("orders.urls")),
    path("", RedirectView.as_view(pattern_name="accounts:restaurant_select", permanent=False), name="home"),
]

handler400 = "hotel_management.views.error_400"
handler403 = "hotel_management.views.error_403"
handler404 = "hotel_management.views.error_404"
handler500 = "hotel_management.views.error_500"

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
