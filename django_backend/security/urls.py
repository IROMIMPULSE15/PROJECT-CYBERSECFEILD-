from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import SSLMonitoringViewSet

router = DefaultRouter()
router.register(r'ssl', SSLMonitoringViewSet, basename='ssl-monitoring')

urlpatterns = [
    path('', include(router.urls)),
] 