from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from waterparkapp.models import UserProfile, Booking, Contact
from django.core.mail import send_mail
from django.conf import settings
import random
import uuid
from django.utils import timezone
import razorpay
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse, JsonResponse
import logging
import threading

# Set up logging
logger = logging.getLogger(__name__)

# Razorpay Client
razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

def generate_otp():
    return str(random.randint(100000, 999999))

def send_email_async(subject, message, from_email, to_email):
    try:
        send_mail(subject, message, from_email, to_email, fail_silently=False, html_message=message)
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")

def home(request):
    # Clear any existing messages to prevent them from persisting
    storage = messages.get_messages(request)
    storage.used = True
    for message in storage:
        pass
    if not request.user.is_authenticated:
        return redirect('login')
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        inquiry_type = request.POST.get('inquiry_type')
        message = request.POST.get('message')

        # Basic validation
        if not all([name, email, inquiry_type, message]):
            messages.error(request, 'Please fill in all required fields.')
            return redirect('home')

        # Save to Contact model
        try:
            Contact.objects.create(
                name=name,
                email=email,
                inquiry_type=inquiry_type,
                message=message
            )
            # Send confirmation email
            subject = 'Thank You for Your Inquiry'
            html_message = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body {{ font-family: Arial, sans-serif; background-color: #f0f8ff; color: #151717; }}
                    .container {{ max-width: 600px; margin: 20px auto; background-color: #fff; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
                    .header {{ background-color: #2d79f3; color: white; text-align: center; padding: 10px; border-radius: 10px 10px 0 0; }}
                    .content {{ padding: 20px; }}
                    .footer {{ text-align: center; font-size: 12px; color: #666; margin-top: 20px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h2>Waterpark Inquiry Confirmation</h2>
                    </div>
                    <div class="content">
                        <p>Dear {name},</p>
                        <p>Thank you for reaching out to us. We have received your inquiry:</p>
                        <p><strong>Inquiry Type:</strong> {inquiry_type}</p>
                        <p><strong>Message:</strong> {message}</p>
                        <p>We will address your inquiry shortly.</p>
                        <p>Thank you for visiting Waterpark!</p>
                        <p>Best regards,<br>Waterpark Team</p>
                    </div>
                    <div class="footer">
                        <p>© 2025 Waterpark. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            threading.Thread(
                target=send_email_async,
                args=(subject, html_message, settings.EMAIL_HOST_USER, [email])
            ).start()
            messages.success(request, 'Your message has been sent successfully!')
        except Exception as e:
            logger.error(f"Failed to save inquiry or send email: {str(e)}")
            messages.error(request, f'Failed to send your message: {str(e)}')
        return redirect('home')
    return render(request, 'index.html')

def register(request):
    # Clear any existing messages
    storage = messages.get_messages(request)
    storage.used = True
    for message in storage:
        pass  # This clears the messages
    if request.method == 'POST':
        username = request.POST.get('username')
        name = request.POST.get('name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        email_otp = request.POST.get('email_otp')

        # Backend validation
        if not username.isalnum():
            messages.error(request, 'Username can only contain letters and numbers (no special characters like @).')
            return redirect('register')

        if not all(char.isalpha() or char.isspace() for char in name):
            messages.error(request, 'Full Name can only contain letters and spaces (no numbers or special characters).')
            return redirect('register')

        email_pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        import re
        if not re.match(email_pattern, email):
            messages.error(request, 'Please enter a valid email address.')
            return redirect('register')

        password_pattern = r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{8,}$'
        if not re.match(password_pattern, password):
            messages.error(request, 'Password must be at least 8 characters long, contain an uppercase letter, a lowercase letter, a number, and a special character (!@#$%^&*).')
            return redirect('register')

        if UserProfile.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists.')
            return redirect('register')
        if UserProfile.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists.')
            return redirect('register')

        # Verify Email OTP
        session_email_otp = request.session.get('email_otp')
        if email_otp != session_email_otp:
            messages.error(request, 'Invalid email OTP. Please try again.')
            return redirect('register')

        # If OTP is valid, create the user
        try:
            user = UserProfile(
                username=username,
                email=email,
                first_name=name,
                is_email_verified=True,
                is_active=True  # Ensure the user is active
            )
            user.set_password(password)  # Hash the password
            user.save()

            # Log user creation for debugging
            logger.debug(f"User created successfully: {username}, Email: {email}")

            # Clear session
            request.session.flush()

            # Include username in the success message
            messages.success(request, f'Registration successful! Your username is {username}. Please login.')
            return redirect('login')
        except Exception as e:
            logger.error(f"Failed to create user: {str(e)}")
            messages.error(request, f'Failed to register: {str(e)}')
            return redirect('register')

    return render(request, 'register.html')

def user_login(request):
    # Clear any existing messages
    storage = messages.get_messages(request)
    storage.used = True
    for message in storage:
        pass  # This clears the messages
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        # Debug: Log the username and password being received
        logger.debug(f"Login attempt - Username: {username}, Password: {password}")
        
        # Authenticate the user
        user = authenticate(request, username=username, password=password)
        if user is not None:
            logger.debug(f"User authenticated successfully: {user.username}")
            if user.is_email_verified:
                if user.is_active:  # Check if the user is active
                    login(request, user)
                    messages.success(request, 'Login successful!')
                    return redirect('home')
                else:
                    messages.error(request, 'Your account is inactive. Please contact support.')
                    logger.debug("User account is inactive.")
            else:
                messages.error(request, 'Please verify your email.')
                logger.debug("User email not verified.")
        else:
            messages.error(request, 'Invalid username or password.')
            logger.debug("Authentication failed: Invalid username or password.")
        return redirect('login')
    return render(request, 'login.html')

def user_logout(request):
    # Clear any existing messages
    storage = messages.get_messages(request)
    storage.used = True
    for message in storage:
        pass  # This clears the messages
    logout(request)
    messages.success(request, 'Logged out successfully!')
    return redirect('login')

def forget_password(request):
    # Clear any existing messages
    storage = messages.get_messages(request)
    storage.used = True
    for message in storage:
        pass  # This clears the messages
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = UserProfile.objects.get(email=email)
            token = str(uuid.uuid4())
            user.reset_token = token
            user.save()
            reset_link = request.build_absolute_uri(f'/reset-password/{token}/')
            # HTML email with sky-blue theme
            html_message = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body {{ font-family: Arial, sans-serif; background-color: #f0f8ff; color: #151717; }}
                    .container {{ max-width: 600px; margin: 20px auto; background-color: #fff; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
                    .header {{ background-color: #2d79f3; color: white; text-align: center; padding: 10px; border-radius: 10px 10px 0 0; }}
                    .content {{ padding: 20px; }}
                    .button {{ display: inline-block; padding: 10px 20px; background-color: #2d79f3; color: white; text-decoration: none; border-radius: 5px; }}
                    .footer {{ text-align: center; font-size: 12px; color: #666; margin-top: 20px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h2>Waterpark Password Reset</h2>
                    </div>
                    <div class="content">
                        <p>Dear {user.first_name},</p>
                        <p>We received a request to reset the password for your account with the username <strong>{user.username}</strong>. Click the button below to reset your password:</p>
                        <a href="{reset_link}" class="button">Reset Password</a>
                        <p>If you didn’t request this, please ignore this email or contact support.</p>
                    </div>
                    <div class="footer">
                        <p>© 2025 Waterpark. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            threading.Thread(
                target=send_email_async,
                args=('Waterpark - Password Reset', html_message, settings.EMAIL_HOST_USER, [email])
            ).start()
            messages.success(request, 'Password reset link has been sent to your email.')
            return redirect('login')
        except UserProfile.DoesNotExist:
            messages.error(request, 'Email not found.')
            return redirect('forget_password')
    return render(request, 'forget_password.html')

def reset_password(request, token):
    # Clear any existing messages
    storage = messages.get_messages(request)
    storage.used = True
    for message in storage:
        pass  # This clears the messages
    try:
        user = UserProfile.objects.get(reset_token=token)
    except UserProfile.DoesNotExist:
        messages.error(request, 'Invalid or expired reset link.')
        return redirect('login')

    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        if new_password == confirm_password:
            user.set_password(new_password)
            user.reset_token = None
            user.save()
            # HTML email with sky-blue theme for reset confirmation
            html_message = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body {{ font-family: Arial, sans-serif; background-color: #f0f8ff; color: #151717; }}
                    .container {{ max-width: 600px; margin: 20px auto; background-color: #fff; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
                    .header {{ background-color: #2d79f3; color: white; text-align: center; padding: 10px; border-radius: 10px 10px 0 0; }}
                    .content {{ padding: 20px; }}
                    .button {{ display: inline-block; padding: 10px 20px; background-color: #2d79f3; color: white; text-decoration: none; border-radius: 5px; }}
                    .footer {{ text-align: center; font-size: 12px; color: #666; margin-top: 20px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h2>Waterpark Password Reset Confirmation</h2>
                    </div>
                    <div class="content">
                        <p>Dear {user.first_name},</p>
                        <p>Your password has been successfully reset for the username <strong>{user.username}</strong>. You can now <a href="{request.build_absolute_uri('/login/')}" class="button">Login</a> with your new password.</p>
                        <p>If you didn’t perform this action, please contact support immediately.</p>
                    </div>
                    <div class="footer">
                        <p>© 2025 Waterpark. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            threading.Thread(
                target=send_email_async,
                args=('Waterpark - Password Reset Confirmation', html_message, settings.EMAIL_HOST_USER, [user.email])
            ).start()
            messages.success(request, 'Password reset successful! Please login.')
            return redirect('login')
        else:
            messages.error(request, 'Passwords do not match.')
            return redirect('reset_password', token=token)
    return render(request, 'reset_password.html')

@login_required
def booking(request):
    # Clear any existing messages to prevent them from persisting
    storage = messages.get_messages(request)
    storage.used = True
    for message in storage:
        pass  # This clears the messages
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        date = request.POST.get('date')
        total_amount = request.POST.get('total_amount')

        try:
            booking_date = timezone.datetime.strptime(date, '%Y-%m-%d').date()
            if booking_date < timezone.now().date():
                messages.error(request, 'Cannot book for past dates.')
                return redirect('booking')
        except ValueError:
            messages.error(request, 'Invalid date format.')
            return redirect('booking')

        ticket_types = {
            'adult': {'name': 'Adult Pass', 'price': 1999},
            'child': {'name': 'Child Pass', 'price': 1499},
            'family': {'name': 'Family Pack', 'price': 6499},
            'special': {'name': 'Special Package', 'price': 7499}
        }
        selected_tickets = []
        total_calculated = 0
        for ticket_type, info in ticket_types.items():
            qty = int(request.POST.get(f'{ticket_type}Qty', 0))
            if qty > 0:
                selected_tickets.append({
                    'type': info['name'],
                    'price': info['price'],
                    'quantity': qty
                })
                total_calculated += qty * info['price']

        if not selected_tickets:
            messages.error(request, 'Please select at least one ticket.')
            return redirect('booking')

        if float(total_amount) != total_calculated:
            messages.error(request, 'Total amount mismatch.')
            return redirect('booking')

        booking = Booking(
            user=request.user,
            ticket_type=', '.join([f"{t['type']} ({t['quantity']})" for t in selected_tickets]),
            price=total_calculated,
            name=name,
            email=email,
            phone_number=phone,
            booking_date=booking_date,
            total_amount=total_calculated,
            ticket_number=str(uuid.uuid4())[:8].upper(),
            payment_status=False
        )
        booking.save()

        amount_in_paisa = int(total_calculated * 100)
        razorpay_order_data = {
            'amount': amount_in_paisa,
            'currency': 'INR',
            'payment_capture': 1
        }
        try:
            razorpay_order = razorpay_client.order.create(data=razorpay_order_data)
            booking.razorpay_order_id = razorpay_order['id']
            booking.save()
            request.session['booking_id'] = booking.id
            request.session['booking_amount'] = amount_in_paisa
            request.session['razorpay_order_id'] = razorpay_order['id']
            return JsonResponse({
                'status': 'success',
                'booking_id': booking.id,
                'amount': amount_in_paisa,
                'razorpay_key': settings.RAZORPAY_KEY_ID,
                'razorpay_order_id': razorpay_order['id']
            })
        except Exception as e:
            logger.error(f"Failed to create Razorpay order: {str(e)}")
            messages.error(request, f'Failed to create payment order: {str(e)}')
            return redirect('booking')

    return render(request, 'booking.html')  # No user context passed

@csrf_exempt
def payment(request):
    # Clear any existing messages
    storage = messages.get_messages(request)
    storage.used = True
    for message in storage:
        pass  # This clears the messages
    booking_id = request.session.get('booking_id')
    if not booking_id:
        messages.error(request, 'No booking found.')
        return redirect('booking')

    try:
        booking = Booking.objects.get(id=booking_id)
    except Booking.DoesNotExist:
        messages.error(request, 'Booking not found.')
        return redirect('booking')

    if request.method == 'POST':
        payment_id = request.POST.get('razorpay_payment_id')
        razorpay_order_id = request.POST.get('razorpay_order_id')
        razorpay_signature = request.POST.get('razorpay_signature')

        if payment_id and razorpay_order_id and razorpay_signature:
            params_dict = {
                'razorpay_order_id': razorpay_order_id,
                'razorpay_payment_id': payment_id,
                'razorpay_signature': razorpay_signature
            }
            try:
                razorpay_client.utility.verify_payment_signature(params_dict)
                payment_details = razorpay_client.payment.fetch(payment_id)
                if payment_details['status'] == 'captured':
                    booking.payment_status = True
                    booking.save()
                    # HTML email with sky-blue theme for booking confirmation
                    html_message = f"""
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <style>
                            body {{ font-family: Arial, sans-serif; background-color: #f0f8ff; color: #151717; }}
                            .container {{ max-width: 600px; margin: 20px auto; background-color: #fff; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
                            .header {{ background-color: #2d79f3; color: white; text-align: center; padding: 10px; border-radius: 10px 10px 0 0; }}
                            .content {{ padding: 20px; }}
                            .details {{ margin: 10px 0; }}
                            .button {{ display: inline-block; padding: 10px 20px; background-color: #2d79f3; color: white; text-decoration: none; border-radius: 5px; }}
                            .footer {{ text-align: center; font-size: 12px; color: #666; margin-top: 20px; }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <div class="header">
                                <h2>Waterpark Booking Confirmation</h2>
                            </div>
                            <div class="content">
                                <p>Dear {booking.name},</p>
                                <p>Your booking has been confirmed! Below are the details:</p>
                                <div class="details">
                                    <strong>Ticket Number:</strong> {booking.ticket_number}<br>
                                    <strong>Ticket Type:</strong> {booking.ticket_type}<br>
                                    <strong>Name:</strong> {booking.name}<br>
                                    <strong>Email:</strong> {booking.email}<br>
                                    <strong>Phone:</strong> {booking.phone_number}<br>
                                    <strong>Date:</strong> {booking.booking_date}<br>
                                    <strong>Total Amount:</strong> ₹{booking.total_amount}
                                </div>
                                <p>Thank you for choosing Waterpark! For any queries, <a href="{request.build_absolute_uri('/#contact')}" class="button">Contact Us</a>.</p>
                            </div>
                            <div class="footer">
                                <p>© 2025 Waterpark. All rights reserved.</p>
                            </div>
                        </div>
                    </body>
                    </html>
                    """
                    threading.Thread(
                        target=send_email_async,
                        args=('Waterpark - Booking Confirmation', html_message, settings.EMAIL_HOST_USER, [booking.email])
                    ).start()
                    # Clear only payment-related session data instead of flushing the entire session
                    if 'booking_id' in request.session:
                        del request.session['booking_id']
                    if 'booking_amount' in request.session:
                        del request.session['booking_amount']
                    if 'razorpay_order_id' in request.session:
                        del request.session['razorpay_order_id']
                    # Return success with redirect URL to homepage
                    return JsonResponse({'status': 'success', 'redirect_url': '/'})
                else:
                    raise Exception('Payment not captured')
            except Exception as e:
                logger.error(f"Payment verification failed: {str(e)}")
                return JsonResponse({'status': 'failure', 'error': str(e)})

    return render(request, 'payment.html', {
        'amount': booking.total_amount,
        'amount_in_paisa': int(booking.total_amount * 100),
        'razorpay_key': settings.RAZORPAY_KEY_ID,
    })

def send_otp_email(request):
    # Clear any existing messages
    storage = messages.get_messages(request)
    storage.used = True
    for message in storage:
        pass  # This clears the messages
    if request.method == 'POST':
        email = request.POST.get('email')
        if email:
            otp = generate_otp()
            request.session['email_otp'] = otp
            # HTML email with sky-blue theme for OTP
            html_message = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body {{ font-family: Arial, sans-serif; background-color: #f0f8ff; color: #151717; }}
                    .container {{ max-width: 600px; margin: 20px auto; background-color: #fff; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
                    .header {{ background-color: #2d79f3; color: white; text-align: center; padding: 10px; border-radius: 10px 10px 0 0; }}
                    .content {{ padding: 20px; }}
                    .otp {{ font-size: 24px; font-weight: bold; color: #2d79f3; text-align: center; margin: 20px 0; }}
                    .footer {{ text-align: center; font-size: 12px; color: #666; margin-top: 20px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h2>Waterpark Email Verification</h2>
                    </div>
                    <div class="content">
                        <p>Dear User,</p>
                        <p>Please use the following OTP to verify your email address:</p>
                        <div class="otp">{otp}</div>
                        <p>This OTP is valid for 10 minutes. If you didn’t request this, please ignore this email.</p>
                    </div>
                    <div class="footer">
                        <p>© 2025 Waterpark. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            threading.Thread(
                target=send_email_async,
                args=('Waterpark Registration - Email OTP', html_message, settings.EMAIL_HOST_USER, [email])
            ).start()
            return JsonResponse({'status': 'success'})
        return JsonResponse({'status': 'failure', 'error': 'Invalid email'})
    return JsonResponse({'status': 'failure', 'error': 'Invalid request'})

def check_otp(request):
    # Clear any existing messages
    storage = messages.get_messages(request)
    storage.used = True
    for message in storage:
        pass  # This clears the messages
    if request.method == 'POST':
        otp = request.POST.get('otp')
        key = request.POST.get('key')
        session_otp = request.session.get(key)
        return JsonResponse({'status': 'success', 'valid': otp == session_otp})
    return JsonResponse({'status': 'failure', 'valid': False})

def test_email(request):
    # Clear any existing messages
    storage = messages.get_messages(request)
    storage.used = True
    for message in storage:
        pass  # This clears the messages
    try:
        send_mail(
            'Test Email',
            'This is a test email to verify SMTP configuration.',
            settings.EMAIL_HOST_USER,
            ['Sonugedar822@gmail.com'],
            fail_silently=False,
        )
        return HttpResponse("Email sent successfully!")
    except Exception as e:
        return HttpResponse(f"Email sending failed: {str(e)}")