from django.urls import path


from . import views

urlpatterns = [
    path('register-user/', view=views.SignUpView().as_view(), name='register-user'),
    path('activate-account/<uidb64>/<token>/', view=views.ActivateAccountView().as_view(),
         name='activate-account'),

    path('login/', view=views.LoginView.as_view(), name='login'),
    path('logout/', view=views.UserLogoutView.as_view(), name='logout'),

    path("change-password/", view=views.ChangePasswordView.as_view(), name="change-password"),

    path('get-refresh-token/', view=views.CustomTokenRefreshView.as_view(),
         name='get-refresh-token')
]
