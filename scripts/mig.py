from flask_migrate import upgrade

def go():
    upgrade()
