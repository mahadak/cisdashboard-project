from django.urls import path
from django.urls.conf import include
from dashboard import views

app_name = "dashboard"
urlpatterns = [
    path("dashboard/", views.DashboardView.as_view(), name="dashboard"),
    path("connections/", views.ConnectionsView.as_view(), name="connections"),
    path("scanconnection/", views.ScanConnectionView.as_view(), name="scanconnection"),
    path("scanreports/", views.ScanReportsView.as_view(), name="scanreports"),
    path("scanreportdetail/<uuid:uuid>", views.ScanReportDetailView.as_view(), name="scanreportsdetail"),
    path("reportdetail/<uuid:uuid>", views.ReportDetailView.as_view(), name="reportsdetail"),
    path("iampolicies/", views.IamPolicyView.as_view(), name="iampolicies"),
    path("iamrepresent/<uuid:uuid>", views.IamPolicyGraphicalView.as_view(), name="iamrepresent"),
    path("awscrossconnection/", views.CrossSignInAWS.as_view(), name="awscrossconnection"),
]