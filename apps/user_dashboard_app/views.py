from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.sessions.models import Session
from .models import User, Message, Comment
import re, bcrypt
# User.objects.create(first_name='Chris', last_name='Kenimer', email='ckenimer@hotmail.com')
# Create your views here.
def index(request):
    return render(request, 'user_dashboard_app/index.html')
def login_page(request):
    return render(request, 'user_dashboard_app/login.html')
def login_user(request):
    if request.POST:
        check_user = User.objects.login(request.POST)
        if check_user[0]:
            request.session['user'] = {
                'name': check_user[1].first_name + ' ' + check_user[1].last_name,
                'id': check_user[1].id,
                'permission_level': check_user[1].permission_level
            }
        else:
            for error in check_user[1]:
                messages.warning(request, error)
                return redirect('/login')
    return redirect('/dashboard')
def register_page(request):
    return render(request, 'user_dashboard_app/register.html')
def register_user(request):
    if request.POST:
        validate_user_fields = User.objects.validate_user_fields(request.POST)
        if validate_user_fields[0]:
            check_for_users = User.objects.all()
            hashed_pw = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
            if check_for_users:
                new_user = User.objects.create(first_name=request.POST['first_name'], last_name=request.POST['last_name'], email=request.POST['email'], password=hashed_pw, permission_level = 1)
            else:
                new_user = User.objects.create(first_name=request.POST['first_name'], last_name=request.POST['last_name'], email=request.POST['email'], password=hashed_pw, permission_level = 9)
            request.session['user'] = {
                'name': new_user.first_name + ' ' + new_user.last_name,
                'id': new_user.id,
                'permission_level': new_user.permission_level
            }
        else:
            for error in validate_user_fields[1]:
                messages.warning(request, error[1])

            return redirect('/register')
    return redirect('/dashboard')
def dashboard(request):
    users = User.objects.all()
    context = {
        'users': users
    }
    return render(request, 'user_dashboard_app/dashboard.html', context)
def edit_user(request, id):
    user = User.objects.get(id=id)
    context = {
        'user': user
    }
    return render(request, 'user_dashboard_app/register.html', context)
def update_user(request):
    if request.POST:
        user = 'existing'
        validate_user_fields = User.objects.validate_user_fields(request.POST, user=user)
        if validate_user_fields[0]:
            check_for_emails = User.objects.get(email=request.POST['email'])
            if int(request.POST['user_id']) == check_for_emails.id:
                print 'This email is the users email'
            else:
                messages.warning(request, 'This email address has been taken')
                return redirect('edit_user/'+request.POST['user_id'])
            if validate_user_fields:
                if len(request.POST['password']) > 0:
                    if not request.POST['password'] == request.POST['confirm_password']:
                        messages.warning(request,['password_match_error', 'Password fields do not match'])
                    elif not re.search(r'^(?=.*[a-z])(?=.*\d)(?=.*[A-Z])(?:.{8,})$', request.POST['password']):
                        messages.warning(request, ['length_complexity', 'Requirements: 8 Characters, Capital letters, and numbers'])
                    else:
                        hashed_pw = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
                        User.objects.filter(id=int(request.POST['user_id'])).update(first_name=request.POST['first_name'], last_name=request.POST['last_name'], email=request.POST['email'], password=hashed_pw, description=request.POST['description'])
                else:
                    User.objects.filter(id=int(request.POST['user_id'])).update(first_name=request.POST['first_name'], last_name=request.POST['last_name'], email=request.POST['email'], description=request.POST['description'])
        else:
            for error in validate_user_fields[1]:
                messages.warning(request, error[1])
                return redirect('edit_user/'+request.POST['user_id'])

            return redirect('/register')
    return redirect('/dashboard')
def profile(request, id):
    users = User.objects.filter(id=id)
    context = {
        'users': users
    }
    return render(request, 'user_dashboard_app/dashboard.html', context)
def user_information(request, id):
    user = User.objects.get(id=id)
    profile_messages = Message.objects.filter(profile_user=user)
    comments = Comment.objects.filter(profile_user=user)
    context = {
        'user': user,
        'profile_messages': profile_messages,
        'comments': comments,
    }
    return render(request, 'user_dashboard_app/user_information.html', context)
def new_message(request):
    user_profile = User.objects.get(id=int(request.POST['user_id']))
    commentor = User.objects.get(id=int(request.session['user']['id']))
    print request.POST['comment']
    print user_profile
    print commentor
    # print request.session['user']['id']
    new_message = Message.objects.create(message_details=request.POST['comment'], user_commentor=commentor, profile_user=user_profile)
    print new_message
    return redirect('/dashboard')
def new_comment(request):
    user_profile = User.objects.get(id=int(request.POST['profile_id']))
    commentor = User.objects.get(id=int(request.session['user']['id']))
    message = Message.objects.get(id=int(request.POST['message_id']))
    new_comment = Comment.objects.create(message_details=request.POST['comment'], profile_user=user_profile, user_commentor=commentor, parent_message=message)
    return redirect('/user_information/'+request.POST['profile_id'])
def purge_users(request):
    User.objects.delete_all()
    Comment.objects.delete_all()
    Message.objects.delete_all()
    return redirect('/dashboard')
