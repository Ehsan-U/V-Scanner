from django.urls import path
from .views import home,result,fetch_pdf,v_inputs


urlpatterns = [
    path("",home,name="home"),
    path("result/",result,name="result"),
    path("pdf/",fetch_pdf,name="report"),
    path("v_inputs/",v_inputs,name="v_inputs"),
]
