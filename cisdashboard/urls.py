from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from dashboard.views import DashboardView
from users.decorators import is_logged_in
from users.views import LoginView
from django.conf import settings

urlpatterns = [
                  path('admin/', admin.site.urls),
                  path("users/", include("users.urls")),
                  path("management/", include("dashboard.urls")), 
                  path("login/", LoginView.as_view(), name="login"),
                  path('', is_logged_in(DashboardView.as_view()), name=""),
              ]
urlpatterns += static(settings.STATIC_URL,document_root=settings.STATIC_ROOT) 