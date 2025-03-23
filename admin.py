from django.contrib import admin
from waterparkapp.models import UserProfile, Booking, Contact
@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('username', 'first_name', 'email', 'phone_number', 'is_email_verified')  # Removed 'is_phone_verified'
    search_fields = ('username', 'email', 'phone_number')
    list_filter = ('is_email_verified',)  # Removed 'is_phone_verified'

@admin.register(Booking)
class BookingAdmin(admin.ModelAdmin):
    list_display = ('ticket_number', 'user', 'ticket_type', 'price', 'name', 'email', 'phone_number', 'booking_date', 'total_amount', 'payment_status', 'created_at')
    search_fields = ('ticket_number', 'user__username', 'name', 'email', 'phone_number')
    list_filter = ('payment_status', 'booking_date', 'ticket_type')
    date_hierarchy = 'booking_date'

@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    list_display = ('name', 'email','inquiry_type', 'message', 'created_at')
    search_fields = ('name', 'email')
    date_hierarchy = 'created_at'