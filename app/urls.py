from django.urls import path

from app.views import GetUserRecordAPIView, OrganisationListCreateAPIView, GetOrganisationRecordAPIView, \
    AddUserToOrganisationAPIView

urlpatterns = [
    path('users/<uuid:userId>', GetUserRecordAPIView.as_view()),
    path('organisations', OrganisationListCreateAPIView.as_view()),
    path('organisations/<uuid:orgId>', GetOrganisationRecordAPIView.as_view(), name='organisation-detail'),
    path('organisations/<uuid:orgId>/users', AddUserToOrganisationAPIView.as_view()),
]