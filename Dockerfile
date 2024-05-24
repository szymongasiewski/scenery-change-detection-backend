FROM python:3.11.3-slim

RUN apt-get update && apt-get install -y libglib2.0-0
RUN apt-get update && apt-get install -y libgl1-mesa-glx

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . /app/

EXPOSE 8000

CMD ["sh", "-c", "python manage.py migrate && python manage.py runserver 0.0.0.0:8000"]