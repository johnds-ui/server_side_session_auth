from django import forms

from .models import MenuItem, Category


class MenuItemAdminForm(forms.ModelForm):
    class Meta:
        model = MenuItem
        fields = ["category", "name", "description", "price", "image", "available"]

    def __init__(self, *args, restaurant=None, **kwargs):
        super().__init__(*args, **kwargs)
        if restaurant is not None:
            self.fields["category"].queryset = Category.objects.filter(
                restaurant=restaurant
            ).order_by("name")
        else:
            self.fields["category"].queryset = Category.objects.order_by("name")


class CategoryAdminForm(forms.ModelForm):
    class Meta:
        model = Category
        fields = ["name", "description"]
