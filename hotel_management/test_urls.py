from django.core.exceptions import PermissionDenied, SuspiciousOperation
from django.http import HttpResponse
from django.urls import path

from .urls import urlpatterns as project_urlpatterns


def raise_bad_request(request):
    raise SuspiciousOperation("bad request")


def raise_forbidden(request):
    raise PermissionDenied("forbidden")


def ok_404_response(request):
    return HttpResponse(status=404)


def raise_server_error(request):
    raise RuntimeError("server error")


urlpatterns = [
    *project_urlpatterns,
    path("test-400/", raise_bad_request),
    path("test-403/", raise_forbidden),
    path("test-404-response/", ok_404_response),
    path("test-500/", raise_server_error),
]
