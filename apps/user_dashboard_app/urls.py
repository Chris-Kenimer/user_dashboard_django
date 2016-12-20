from django.conf.urls import url
from . import views
urlpatterns = [
    url(r'^$', views.index, name = 'index'),
    url(r'^dashboard$', views.dashboard, name = 'dashboard'),
    url(r'^register$', views.register_page, name='register_page'),
    url(r'^register_user$', views.register_user, name='register_user'),
    url(r'^login$', views.login_page, name='login_page'),
    url(r'^login_user$', views.login_user, name='login_user'),
    url(r'^profile/(?P<id>\d+$)', views.profile, name='profile'),
    url(r'user_information/(?P<id>\d+$)', views.user_information, name='user_information'),
    url(r'^edit_user/(?P<id>\d+$)', views.edit_user, name='edit_user'),
    url(r'^update_user', views.update_user, name='update_user'),
    url(r'^delete_all_users$', views.purge_users),
    url(r'^message$', views.new_message, name='new_message'),
    url(r'^comment$', views.new_comment, name='message_comment'),
    # url(r'^remove/(?P<id>\d+$)', views.remove),
    # url(r'^logout$', views.logout)
    # url(r'^courses/add$', views.add),
    # url(r'courses/confirm_destroy/(?P<id>\d+$)', views.confirm_destroy),
    # url(r'courses/destroy/(?P<id>\d+$)', views.destroy)

]
