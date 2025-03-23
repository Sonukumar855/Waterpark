from django.db import models
from django.contrib.auth.models import AbstractUser

class UserProfile(AbstractUser):
    phone_number = models.CharField(max_length=15, unique=True, null=True, blank=True)
    is_email_verified = models.BooleanField(default=False)
    reset_token = models.CharField(max_length=36, null=True, blank=True)  # For password reset

    def __str__(self):
        return self.username

class Booking(models.Model):
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    ticket_type = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    name = models.CharField(max_length=100)
    email = models.EmailField()
    phone_number = models.CharField(max_length=15)
    booking_date = models.DateField()
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_status = models.BooleanField(default=False)
    ticket_number = models.CharField(max_length=50, unique=True, null=True, blank=True)
    razorpay_order_id = models.CharField(max_length=100, null=True, blank=True)  # For Razorpay
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ticket_type} - {self.user.username}"

class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    inquiry_type = models.CharField(max_length=50, blank=True, null=True)  # Added inquiry_type field
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.email}"