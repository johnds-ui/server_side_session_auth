from django import forms


class UserLoginForm(forms.Form):
    """Email + password login — credentials sent to Flask auth service."""
    email = forms.EmailField(
        label="Email",
        widget=forms.EmailInput(attrs={"autocomplete": "email", "autofocus": True}),
    )
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )


class UserRegisterForm(forms.Form):
    """Registration form — validated and created in Flask auth service."""
    email = forms.EmailField(
        label="Email",
        widget=forms.EmailInput(attrs={"autocomplete": "email"}),
    )
    password1 = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
    )
    password2 = forms.CharField(
        label="Confirm Password",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
    )

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get("password1", "")
        p2 = cleaned.get("password2", "")
        if p1 and p2 and p1 != p2:
            raise forms.ValidationError("Passwords do not match.")
        if p1 and len(p1) < 8:
            raise forms.ValidationError("Password must be at least 8 characters.")
        return cleaned


class AdminReauthForm(forms.Form):
    """Confirm identity before sensitive admin operations."""
    password = forms.CharField(
        label="Confirm Your Password",
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password", "autofocus": True}),
    )


class AddStaffForm(forms.Form):
    """Add a waiter to the admin's restaurant (restaurant_admin only)."""
    email = forms.EmailField(
        label="Email",
        widget=forms.EmailInput(attrs={"autocomplete": "email", "autofocus": True}),
    )
    password = forms.CharField(
        label="Temporary Password",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
    )
    role = forms.ChoiceField(
        label="Role",
        choices=[("waiter", "Waiter")],
        initial="waiter",
    )

    def clean_password(self):
        pw = self.cleaned_data.get("password", "")
        if len(pw) < 8:
            raise forms.ValidationError("Password must be at least 8 characters.")
        return pw


class RestaurantAdminRegisterForm(forms.Form):
    """One-time registration form for a restaurant admin account."""
    restaurant_name = forms.CharField(
        label="Restaurant Name",
        max_length=120,
        widget=forms.TextInput(attrs={"autofocus": True, "placeholder": "e.g. The Grand Bistro"}),
    )
    email = forms.EmailField(
        label="Email",
        widget=forms.EmailInput(attrs={"autocomplete": "email"}),
    )
    password1 = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
    )
    password2 = forms.CharField(
        label="Confirm Password",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
    )

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get("password1", "")
        p2 = cleaned.get("password2", "")
        if p1 and p2 and p1 != p2:
            raise forms.ValidationError("Passwords do not match.")
        if p1 and len(p1) < 8:
            raise forms.ValidationError("Password must be at least 8 characters.")
        return cleaned


class UserAdminUpdateForm(forms.Form):
    """Minimal user-edit form used in the admin dashboard."""
    ROLE_CHOICES = [
        ("customer", "Customer"),
        ("waiter", "Waiter"),
        ("restaurant_admin", "Restaurant Admin"),
    ]

    email = forms.EmailField(label="Email")
    role = forms.ChoiceField(label="Role", choices=ROLE_CHOICES)
    is_active = forms.BooleanField(label="Active", required=False)
