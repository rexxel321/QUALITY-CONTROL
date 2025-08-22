from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Submission

@login_required
def dashboard(request):
    new_submissions = Submission.objects.filter(status='Pending').count()
    approved = Submission.objects.filter(status='Approved').count()
    rejected = Submission.objects.filter(status='Rejected').count()
    recent_submissions = Submission.objects.order_by('-date_submitted')[:5]
    context = {
        'new_submissions': new_submissions,
        'approved': approved,
        'rejected': rejected,
        'recent_submissions': recent_submissions,
        'user': request.user
    }
    return render_template(request, 'core/dashboard.html', context)

@login_required
def submission_action(request, submission_id, action):
    submission = Submission.objects.get(id=submission_id)
    if action in ['approve', 'reject']:
        submission.status = action.capitalize()
        submission.save()
        messages.success(request, f'Submission {submission_id} {action}d!')
    return redirect('dashboard')