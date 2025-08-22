from django.db import models
from django.contrib.auth.models import User
from django.core.files.storage import FileSystemStorage

# Custom storage untuk uploads
fs = FileSystemStorage(location='uploads/')

class Submission(models.Model):
    STATUS_CHOICES = (
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected'),
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    app_name = models.CharField(max_length=100)
    file_path = models.FileField(upload_to='submissions/', storage=fs)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    date_submitted = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.app_name} by {self.user.username}"