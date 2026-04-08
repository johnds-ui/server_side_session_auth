from django.shortcuts import render


def render_error_page(request, template_name, status_code):
    return render(request, template_name, status=status_code)


def error_400(request, exception=None):
    return render_error_page(request, "400.html", 400)


def error_403(request, exception=None):
    return render_error_page(request, "403.html", 403)


def csrf_failure(request, reason=""):
    return render_error_page(request, "403.html", 403)


def error_404(request, exception=None):
    return render_error_page(request, "404.html", 404)


def error_500(request):
    return render_error_page(request, "500.html", 500)
