from app import app, db
from app import Post, Category, Comment, User

with app.app_context():
    # Create the tables
    db.create_all()
    print("Tables created successfully!")

    # Add a new category
    py = Category(name='Python')
    db.session.add(py)
    db.session.commit()  # Commit to save the category to the database

    # Ensure a user exists
    user = User.query.first()  # Try to get an existing user
    if not user:
        user = User(name='Test User', username='testuser', password='hashedpassword', email='testuser@example.com', phone='123456789')
        db.session.add(user)
        db.session.commit()

    # Add a post with the new category and associate it with the user
    post1 = Post(title="My first post", subtitle="Ain't ya proud?", body="[content goes here]", category=py, user_id=user.id)
    db.session.add(post1)
    db.session.commit()  # Commit to save the post to the database

    # Add a comment associated with the post and user
    comment = Comment(body="hey there", post_id=post1.id, user_id=user.id)
    db.session.add(comment)
    db.session.commit()
    print("Data inserted successfully!")
