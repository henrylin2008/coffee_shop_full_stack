import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

# ---------------------------------------------------------------------#
# Initial setups
# ---------------------------------------------------------------------#
app = Flask(__name__)
setup_db(app)
CORS(app)

'''
@TODO uncomment the following line to initialize the database
!! NOTE THIS WILL DROP ALL RECORDS AND START YOUR DB FROM SCRATCH
!! NOTE THIS MUST BE UNCOMMENTED ON FIRST RUN
'''
db_drop_and_create_all()


@app.route('/drinks', methods=['GET'])
def retrieve_drinks():
    """An endpoint to handle GET requests '/drinks'
    Retrieve a list of drinks from database
    Return:
        Status code 200 and json object with
            "success": True or False
            "drinks": the list of drinks
    Raises:
        404: Resource is not found if any drink is not existed.
    """
    drink_query = Drink.query.all()
    drinks = [drink.short() for drink in drink_query]

    if len(drinks) == 0:
        abort(404)

    return jsonify({
        'success': True,
        'drinks': drinks
    }), 200


@app.route('/drinks-detail', methods=['GET'])
@requires_auth('get:drinks-detail')
def retrieve_drinks_detail(payload):
    """An endpoint to handle GET requests '/drinks-detail'
    Retrieve the drink.long() data representation when the request
    user is valid.
    Arguments:
        payload (dict): decoded jwt payload
    Returns:
        Status code 200 and json object with
            "success": True or False
            "drinks": the list of drinks
    Raises:
        404: Resource is not found if any drink is not existed.
    """
    all_drinks = Drink.query.all()
    if all_drinks is None:
        abort(404)

    return jsonify({
        'success': True,
        'drinks': [drink.long() for drink in all_drinks]
    }), 200


@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')
def add_drink(payload):
    """An endpoint to handle POST request '/drinks'
    Add a new drink in the drinks table when the request user have
    a proper permission.
    Arguments:
        payload (dict): decoded jwt payload
    Returns:
        Status code 200 and json object with
            "success": True or False
            "drinks": a list of drink containing only the newly
                    created drink
    Raises:
        400: Title or recipe has not been submitted.
        422: Request is unprocessable.
    """
    body = request.get_json()
    drink_title = body.get('title', None)
    drink_recipe = body.get('recipe', None)
    if not drink_title or not drink_recipe:
        return jsonify({
            'success': False,
            'error': 400,
            'message': 'Title and recipe must be submitted.'
        }), 400

    drink = Drink(title=drink_title, recipe=json.dumps(drink_recipe))
    print(drink)

    try:
        drink.insert()

        return jsonify({
            'success': True,
            'drinks': [drink.long()]
        }), 200

    except Exception:
        abort(422)


@app.route('/drinks/<int:drink_id>', methods=['PATCH'])
@requires_auth('patch:drinks')
def update_drink(payload, drink_id):
    """An endpoint to handle PATCH request '/drinks/<int:drink_id>'
    Update the name or recipe of the designated drinks.
    It is permitted for users who have the proper validations.
    Arguments:
        payload (dict): decoded jwt payload
        drink_id (int): drinke id which is wanted to update
    Returns:
        Status code 200 and json object with
            "success": True or False
            "drinks": a list of drink containing only the updated
                    drink
    Raises:
        404: Resource is not found if the drink in request is not existed.
        422: Request is unprocessable.
    """
    drink = Drink.query.filter(Drink.id == drink_id).one_or_none()
    if drink is None:
        abort(404)

    body = request.get_json()
    drink_title = body.get('title', None)
    if drink_title is not None:
        drink.title = drink_title
    drink_recipe = body.get('recipe', None)
    if drink_recipe is not None:
        drink.recipe = json.dumps(drink_recipe)

    try:
        drink.update()

    except Exception as e:
        abort(422)

    return jsonify({
        'success': True,
        'drinks': [drink.long()]
    })


@app.route('/drinks/<int:drink_id>', methods=['DELETE'])
@requires_auth('delete:drinks')
def delete_drink(payload, drink_id):
    """An endpoint to handle DELETE request '/drinks/<int:drink_id>'
    Delete the corresponding row for drink_id. Only users with proper
    permission can delete drinks.
    Arguments:
        payload (dict): decoded jwt payload
        drink_id (int): drink id which is wanted to update
    Returns:
        Status code 200 and json object with
            "success": True or False
            "drinks": the id of the deleted drink
    Raises:
        404: Resource is not found if the drink in request is not existed.
        422: Request is unprocessable.
    """
    drink = Drink.query.get(drink_id)
    if drink is None:
        abort(404)
    try:
        drink.delete()

        return jsonify({
            'success': True,
            'delete': drink.id
        }), 200
    except Exception:
        abort(422)


# ---------------------------------------------------------------------#
# Error Handlers
# ---------------------------------------------------------------------#
'''
Example error handling for unprocessable entity
'''


@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        "success": False,
        "error": 400,
        "message": "Bad request"
    }), 400


@app.errorhandler(401)
def not_found(error):
    return jsonify({
        "success": False,
        "error": 401,
        "message": "Not authorized"
    }), 404


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": 404,
        "message": "Resource not found"
    }), 404


@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        "success": False,
        "error": 405,
        "message": "Method not allowed"
    }), 405


@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 422,
        "message": "Unprocessable"
    }), 422


@app.errorhandler(500)
def server_error(error):
    return jsonify({
        "success": False,
        "error": 500,
        "message": "Internal server error"
    }), 500


@app.errorhandler(AuthError)
def unauthorized(error):
    return


'''
@TODO implement error handler for AuthError
    error handler should conform to general task above 
'''
