from flask import Flask,jsonify,make_response,render_template,request, redirect, url_for
from flask_restful import Resource, Api
from flask import request
import uuid
from models import Product, db, User, Contact, AboutUs
from flask_uploads import UploadSet, IMAGES
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from flask import request

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask.views import View


app = Flask(__name__)


app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True


app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
jwt = JWTManager(app)
# initialize the app with the extension
api = Api(app)
# db.init_app(app)


# @app.before_first_request
# def create_table():
#     db.create_all()


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated



class ProductView(Resource):
    def get(self):
        product = Product.query.all()
        return {'product':list(x.json() for x in product)} 
    def post(self):
        data = request.get_json()
        new_product = Product(data['name'],data['description'],data['price'],data['brand'])
        db.session.add(new_product)
        db.session.commit()
        db.session.flush()
        return new_product.json(),201  

class SingleProduct(Resource):
    def get(self,id):
        product= Product.query.filter_by(id=id).first()
        if product:
            return product.json()
        return {'message':'Product not found'},404
    def delete(self,id):
        product= Product.query.filter_by(id=id).first()
        if product:
            db.session.delete(product)
            db.session.commit()
            return {'message':'Product deleted'}
        return {'message':'Product not found'},404 


    def put(self,id):
        data= request.get_json()
        product= Product.query.filter_by(id=id).first()
        if product:
            product.name=data['name']
            product.description=data['description']
            product.price=data['price']
            product.brand=data['brand']
        else:
            product=Product(id=id,**data)
        db.session.add(product)
        db.session.commit()
        return product.json()

class UserView(Resource):
    def get(self):
        users = User.query.all()
        output = [{'public_id': user.public_id, 'name': user.name, 'password': user.password, 'admin': user.admin} for user in users]
        return jsonify({'users': output})
        
    def post(self):
        data = request.get_json()
        hashed_password = generate_password_hash(data['password'], method='sha256')
        new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message' : 'New user created!'}) 


class OneUserView(Resource):
    def get(self, id):
        user = User.query.filter_by(id=id).first()
        if not user:
            return jsonify({'message': 'User not found'})
        output = {'public_id': user.public_id, 'name': user.name, 'password': user.password, 'admin': user.admin}
        return jsonify({'user': output})

    def delete(self, id):
        user = User.query.filter_by(id=id).first()
        if not user:
            return jsonify({"message":"user not found"}) 
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message":'user delete Successfully'}) 

    def put(self, id):
        user = User.query.filter_by(id=id).first()
        if not user:
            return jsonify({'message': 'User not found'})
        data = request.get_json()
        if 'name' in data:
            user.name = data['name']
        if 'password' in data:
            user.password = generate_password_hash(data['password'])
        if 'admin' in data:
            user.admin = data['admin']
        db.session.commit()
        return jsonify({'message': 'User updated'})

class ContactView(Resource):
    def get(self):
        contact = Contact.query.all()
        return {'contact':list(x.json() for x in contact)}
    def post(self):
        data = request.get_json()
        new_product = Contact(data['name'], data['email'], data['subject'])
        db.session.add(new_product)
        db.session.commit()
        db.session.flush()
        return new_product.json(),201

class SingleContactView(Resource):
    def get(self,id):
        product= Contact.query.filter_by(id=id).first()
        if product:
            return product.json()
        return {'message':'Product not found'},404
    def delete(self,id):
        product= Contact.query.filter_by(id=id).first()
        if product:
            db.session.delete(product)
            db.session.commit()
            return {'message':'Product deleted'}
        return {'message':'Product not found'},404



api.add_resource(ContactView, '/contactus')
api.add_resource(SingleContactView, '/contactus/<int:id>')
api.add_resource(ProductView,'/product')
api.add_resource(SingleProduct,'/product/<int:id>')
api.add_resource(UserView,'/user')
api.add_resource(OneUserView, '/user/<int:id>')

# @app.route('/login')
# def login():
#     auth = request.authorization

#     if not auth or not auth.username or not auth.password:
#         return make_response('Invalid login details', 401)

#     user = User.query.filter_by(name=auth.username).first()

#     if not user or not check_password_hash(user.password, auth.password):
#         return make_response('Invalid login details', 401)

#     token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

#     return jsonify({'token': token})


@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("name", None)
    password = request.json.get("password", None)
    # if username != "test" or password != "test":
    #     return jsonify({"msg": "Bad username or password"}), 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)


@app.route("/optionally_protected", methods=["GET"])
@jwt_required(optional=True)
def optionally_protected():
    current_identity = get_jwt_identity()
    if current_identity:
        return jsonify(logged_in_as=current_identity)
    else:
        return jsonify(logged_in_as="anonymous user")

# email 
from flask_mail import Mail, Message
mail = Mail(app)
@app.route('/mail')
def email():
    msg = Message('Hello Message', sender='admin@test.com', recipients=['to@test.com'])
    mail.send(msg)

# @app.route('/')
# def index():
#     data= Product.query.all()
#     return render_template('index.html',data=data)

from flask import request, redirect, url_for

@app.route('/', methods=['GET', 'POST','DELETE'])
def index():
    if request.method == 'POST':
        data = request.form
        new_info = Contact(data['name'], data['email'], data['subject'])
        db.session.add(new_info)
        db.session.commit()
        db.session.flush()
        return redirect(url_for('index'))

    elif request.method == 'GET':
        product = Product.query.all()
        contact = Contact.query.all()
        print(product)
        return render_template('index.html', product=product,contact=contact)

    # elif request.method == 'DELETE':
    #     data = request.get_json()
    #     print(data)
    #     product_id = data.get('id')
    #     if product_id:
    #         product = Product.query.get(product_id)
    #         if product:
    #             db.session.delete(product)
    #             db.session.commit()
    #             return {'message': 'Product deleted successfully'}, 200
    #         else:
    #             return {'error': 'Product not found'}, 404
    #     else:
    #         return {'error': 'Product id is required'}, 400
    
    
        


@app.route('/about', methods=['GET', 'POST','DELETE'])
def about():
    if request.method == 'POST':
        data = request.form
        new_info = AboutUs(data['title'], data['description'])
        db.session.add(new_info)
        db.session.commit()
        db.session.flush()
        return redirect(url_for('index'))
    elif request.method == 'GET':
        abouts = AboutUs.query.all()
        print(abouts)
        return render_template('about.html')






@app.route('/contact',methods=['GET', 'POST','DELETE'])
def contact():
    if request.method == 'POST':
        data = request.form
        new_info = Contact(data['name'], data['email'], data['subject'])
        db.session.add(new_info)
        db.session.commit()
        db.session.flush()
        return redirect(url_for('index'))

    # if request.method == 'POST':
    #     data = request.get_json()
    #     new_info = Contact(data['name'], data['email'], data['subject'])
    #     db.session.add(new_info)
    #     db.session.commit()
    #     db.session.flush()
    #     return new_info.json(),201


    elif request.method == 'GET':
        contact = Contact.query.all()
        print(contact)
        return render_template('contact.html', contact=contact)



@app.route('/blog')
def blog():
    return render_template("blog.html")

@app.route('/services')
def service():
    return render_template('services.html')
@app.route('/single_blog')
def single_blog():
    return render_template('blog-single.html')

## class base 
# app.add_url_rule('/', view_func=IndexView.as_view('index'))

# @app.route('/', methods=['GET', 'POST'])
# def index():
#     view = IndexView()
#     if request.method == 'GET':
#         return view.dispatch_request()
#     elif request.method == 'POST':
#         return view.dispatch_request()



if __name__ == "__main__":
    db.init_app(app)
    with app.app_context():
        db.create_all()
    app.run()