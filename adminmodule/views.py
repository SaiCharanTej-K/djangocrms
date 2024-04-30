from django.shortcuts import render,redirect

# Create your views here.
def projecthomepage(request):
    return render(request,'projecthomepage.html')
def employerhomepage(request):
    return render(request,'employerhomepage.html')
def jobseekerhomepage(request):
    return render(request,'jobseekerhomepage.html')

"""def signup(request):
    return render(request,'signup.html')

from django.contrib import messages
from django.contrib.auth.models import User,auth
   def signup1(request):
    if request.method=='POST':
        username=request.POST['username']
        pass1=request.POST['password']
        pass2=request.POST['password1']
        if pass1==pass2:
            if User.objects.filter(username=username).exists():
                messages.info(request,'OOPS! Username Already taken.')
                return render(request,'signup.html')
            else:
                user=User.objects.create_user(username=username,password=pass1)
                user.save()
                messages.info(request,'Account Created Successfully')
                return render(request,'projecthomepage.html')
        else:
            messages.info(request,'Password does not match.')
            return render(request,'signup.html')
import re

from django.contrib.auth.models import User, auth
from django.shortcuts import render, redirect
from django.contrib import messages
import re

   def signup1(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        confirm_password = request.POST['password1']

        # Validate password
        if not re.match(r"^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d#$%@!*]{8,}$", password):
            messages.error(request, 'Password must contain at least 8 characters, including at least one letter, one digit, and one special character (#, $, %, @, *, !, or *).')
            return render(request, 'signup.html')

        # Check if passwords match
        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'signup.html')

        # Check if username is numeric and has length 10 for student signup
        if len(username) == 10 and username.isdigit():
            # Create user
            user = User.objects.create_user(username=username, password=password)
            messages.success(request, 'Student account created successfully.')
            return redirect('login')

        # Check if username has length 4 for company signup
        elif len(username) >= 3:
            # Create user
            user = User.objects.create_user(username=username, password=password)
            messages.success(request, 'Company account created successfully.')
            return redirect('login')

        else:
            messages.error(request, 'Invalid username format.')
            return render(request, 'signup.html')

    else:
        return render(request, 'signup.html')
import re
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib import messages


def login(request):
    return render(request,'login.html')
   def login1(request):
    if request.method=='POST':
        username=request.POST['username']
        pass1=request.POST['password']
        user=auth.authenticate(username=username,password=pass1)
        if user is not None:
            auth.login(request,user)
            if len(username)==10:
                return redirect('jobseekerhomepage')
            elif len(username)==4:
                return redirect('employerhomepage')
            else:
                return redirect('projecthomepage')
        else:
            messages.info(request,'Invalid Credentials')
            return render(request,'login.html')

    else:
        return render(request, 'login.html')
   def login1(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        # Check if username and password meet company signup constraints
        if len(username) >= 3:
            # Authenticate user
            user = auth.authenticate(username=username, password=password)
            if user is not None:
                auth.login(request, user)
                return redirect('employerhomepage')
            else:
                messages.error(request, 'Invalid username or password.')
                return render(request, 'login.html')

        # Check if username and password meet student signup constraints
        elif len(username) == 10 and username.isdigit():
            # Authenticate user
            user = auth.authenticate(username=username, password=password)
            if user is not None:
                auth.login(request, user)
                return redirect('jobseekerhomepage')
            else:
                messages.error(request, 'Invalid username or password.')
                return render(request, 'login.html')

        else:
            messages.error(request, 'Invalid username or password format.')
            return render(request, 'login.html')

    else:
        return render(request, 'login.html')
def login1(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        # Check if username and password meet company signup constraints
        if len(username) == 4 and re.match(r'^[a-zA-Z0-9]+$', username):
            # Authenticate user
            user = auth.authenticate(username=username, password=password)
            if user is not None:
                auth.login(request, user)
                return redirect('employerhomepage')
            else:
                messages.error(request, 'Invalid username or password.')
                return render(request, 'login.html')

        # Check if username and password meet student signup constraints
        elif len(username) == 10 and username.isdigit():
            # Authenticate user
            user = auth.authenticate(username=username, password=password)
            if user is not None:
                auth.login(request, user)
                return redirect('jobseekerhomepage')
            else:
                messages.error(request, 'Invalid username or password.')
                return render(request, 'login.html')

        else:
            messages.error(request, 'Invalid username or password format.')
            return render(request, 'login.html')

    else:
        return render(request, 'login.html')"""
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User, auth

def signup(request):
    return render(request, 'signup.html')

def signup1(request):
    if request.method == 'POST':
        user_type = request.POST.get('user_type')
        username = request.POST['username']
        pass1 = request.POST['password']
        pass2 = request.POST['password1']

        # Basic password validation
        if len(pass1) < 8:
            messages.error(request, 'Password must be at least 8 characters long.')
            return render(request, 'signup.html')

        if pass1 != pass2:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'signup.html')

        # Differentiate between student and company signup based on username length
        if user_type == 'student' and len(username) != 10:
            messages.error(request, 'Student username must be exactly 10 digits long.')
            return render(request, 'signup.html')

        if user_type == 'company' and len(username) <= 3:
            messages.error(request, 'Company username must be greater than 3 characters long.')
            return render(request, 'signup.html')

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already taken.')
            return render(request, 'signup.html')

        user = User.objects.create_user(username=username, password=pass1)
        user.save()
        messages.success(request, 'Account created successfully.')
        return redirect('login')
    else:
        return render(request, 'signup.html')

def login(request):
    return render(request, 'login.html')

def login1(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = auth.authenticate(username=username, password=password)

        if user is not None:
            auth.login(request, user)
            if len(username) == 10:
                return redirect('jobseekerhomepage')
            elif len(username) >= 3:
                return redirect('employerhomepage')
            else:
                return redirect('projecthomepage')
        else:
            messages.error(request, 'Invalid Credentials')
            return render(request, 'login.html')
    else:
        return render(request, 'login.html')





def logout(request):
    auth.logout(request)
    return render(request,'projecthomepage.html')