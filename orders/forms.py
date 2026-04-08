from django import forms
from .models import Order


class CartAddForm(forms.Form):
    quantity = forms.IntegerField(min_value=1, initial=1)


class OrderCreateForm(forms.ModelForm):
    class Meta:
        model = Order
        fields = ["delivery_details", "table_number", "room_number"]
        widgets = {
            "delivery_details": forms.Textarea(attrs={"rows": 3}),
        }
