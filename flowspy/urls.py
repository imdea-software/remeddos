from django.urls import re_path, include, path
from django.views.generic import TemplateView
from django.conf import settings
from django.contrib import admin
from rest_framework import routers
from django import views
from django.contrib.auth import views as auth_views
from django.conf import settings
from django.conf.urls.static import static
from django.conf.urls.i18n import i18n_patterns
import flowspec.views


from flowspec.viewsets import (
    RouteViewSet,
    PortViewSet,
    ThenActionViewSet,
    FragmentTypeViewSet,
    MatchProtocolViewSet,
    MatchDscpViewSet,
)

admin.autodiscover()

# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter()
router.register(r'routes', RouteViewSet, basename='route')
router.register(r'ports', PortViewSet)
router.register(r'thenactions', ThenActionViewSet)
router.register(r'fragmentypes', FragmentTypeViewSet)
router.register(r'matchprotocol', MatchProtocolViewSet)
router.register(r'matchdscp', MatchDscpViewSet)


urlpatterns = [
    path('',flowspec.views.group_routes,name="index"),
    path('service-desc',flowspec.views.service_desc,name="service-description"),
    re_path(r'^poll/', include('poller.urls')),
    re_path(r'^flowspec/', include('flowspec.urls')),
    #ccre_path(r'^accounts/', include('accounts.urls')),
    path('accounts/', include('allauth.urls')),
    re_path(r'^setlang/?$', views.i18n.set_language),
    re_path(r'^activate/complete/$',TemplateView.as_view(template_name='registration/activation_complete.html'), name='registration_activation_complete'),
    re_path(r'^admin/', admin.site.urls),
    re_path(r'^tinymce/', include('tinymce.urls')),
    re_path(r'^altlogin/?',auth_views.LoginView.as_view(template_name= 'overview/login.html'), name="altlogin"),
    re_path(r'^api/', include(router.urls)),
    re_path(r'^i18n/', include('django.conf.urls.i18n')),
    path('endpoint',flowspec.views.ProcessWebHookView.as_view(),name="endpoint"),     
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

""" if 'graphs' in settings.INSTALLED_APPS:
    from graphs import urls as graphs_urls
    urlpatterns += [
        re_path(r'^graphs/', include(graphs_urls))]


try:
    if settings.DEBUG:
        # only for development / testing mode:
        from django.contrib.staticfiles.urls import staticfiles_urlpatterns
        urlpatterns += staticfiles_urlpatterns()
except:
    pass
 """
 


