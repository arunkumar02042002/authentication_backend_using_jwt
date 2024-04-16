from django.urls import path


from . import views

urlpatterns = [
    path('register-user/', view=views.SignUpView().as_view(), name='register-user'),
    path('activate-account/<uidb64>/<token>/', view=views.ActivateAccountView().as_view(),
         name='activate-account'),
]
