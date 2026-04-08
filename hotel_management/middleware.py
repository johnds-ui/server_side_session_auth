from django.core.exceptions import PermissionDenied, SuspiciousOperation
from django.http import Http404

from .views import error_400, error_403, error_404, error_500


class CustomErrorPageMiddleware:
    """
    Render project error templates even while DEBUG=True so local development
    matches the configured production error pages.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            response = self.get_response(request)
        except Http404 as exception:
            return error_404(request, exception)
        except SuspiciousOperation as exception:
            return error_400(request, exception)
        except PermissionDenied as exception:
            return error_403(request, exception)
        except Exception:
            return error_500(request)

        if response.status_code == 400:
            return error_400(request)
        if response.status_code == 403:
            return error_403(request)
        if response.status_code == 404:
            return error_404(request)
        if response.status_code >= 500:
            return error_500(request)

        return response
