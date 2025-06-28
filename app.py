from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('Homepage.html')

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        # Handle login logic here (e.g., check credentials)
        email = request.form['email']
        password = request.form['password']
        # For now, just redirect to the homepage after "logging in"
        return redirect(url_for('home'))
    return render_template('login_page.html')

if __name__ == '__main__':
    app.run(debug=True)