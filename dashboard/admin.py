from django.contrib import admin
from dashboard.models import UserAWS, ScanReports, ServicesReport
# Register your models here.

admin.site.register(UserAWS)
admin.site.register(ScanReports)
admin.site.register(ServicesReport)