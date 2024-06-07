from django.urls import path
from .views import *

urlpatterns = [
    
    path('register/', UserCreateView.as_view(), name='user-register'),
    path('users/', UserListView.as_view(), name='user-list'),
    path('user/edit/<int:pk>/', UserEditView.as_view(), name='user-edit'),
    path('user/delete/<int:pk>/', UserDeleteView.as_view(), name='user-delete'),
    path('login/', UserLoginView.as_view(), name='user-login'),


    path('event/create/',EventCreateView.as_view(),name='event_create'),
    path('events/', EventListView.as_view(), name='event-list'),
    path('event/edit/<int:pk>/', EventEditView.as_view(), name='event-edit'),
    path('event/delete/<int:pk>/', EventDeleteView.as_view(), name='event-delete'),
   

    path('event/registration/',RegistrationCreateView.as_view(),name='event-register'),
    path('event/registration/list/',RegistrationListView.as_view(),name='registration-list'),
    path('registration/update/<int:pk>/', RegistrationUpdateView.as_view(), name='registration-update'),
    path('registration/delete/<int:pk>/', RegistrationDeleteView.as_view(), name='registration-delete'),
    
]