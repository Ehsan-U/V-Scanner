from django import forms
from django.forms import Form

class CustomForm(Form):
    url = forms.CharField(max_length=100)