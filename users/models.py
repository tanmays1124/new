from django.db import models
from django.contrib.auth.models import AbstractUser


# Create your models here.
class User(AbstractUser):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    username = models.CharField(max_length=255, unique=True,default='')
    photo = models.ImageField(upload_to='user_photos/', null=True, blank=True) 

    # USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []


class QuizHistory(models.Model):
    user = models.ForeignKey(User, related_name='quiz_histories', on_delete=models.CASCADE)
    domain = models.CharField(max_length=255)
    difficulty_level = models.CharField(max_length=20)
    score = models.IntegerField()
    attempted_questions = models.JSONField()
    submission_time = models.DateTimeField(auto_now_add=True)





class QuizQuestion(models.Model):
    # _id = models.ObjectIdField(primary_key = True)
    category = models.CharField(max_length=100)
    difficulty = models.CharField(max_length=10)
    question = models.TextField()
    option_a = models.TextField(default='')
    option_b = models.TextField(default='')
    option_c = models.TextField(default='')
    option_d = models.TextField(default='')
    answer = models.CharField(max_length=1)  # Assuming answer is a single character (a, b, c, or d)

    def __str__(self):
        return f"{self.category} - {self.difficulty} - {self.question}"
    