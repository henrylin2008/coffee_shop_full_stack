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


@app.after_request
def after_request(response):
    """Setting Access-Control-allow

    Parameters:
        response: an instance of response_class

    Return:
        response object with Access-Control-Allow
    """
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,true')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response


"""
Drop all records and start DB from scratch
"""
# db_drop_and_create_all()


@app.route('/drinks', methods=['GET'])
def retrieve_drinks():
    """An endpoint to handle GET requests '/drinks'
    Retrieves a list of drinks with a short description

    Returns:
        -Status code 200 and json object with
            -"success" (boolean): True or False
            -"drinks" (list): a list of drinks

    Raises:
        -404: Resource not found
    """
    drink_query = Drink.query.all()
    drink_short = [drink.short() for drink in drink_query]

    if len(drink_short) == 0:
        abort(404)

    try:
        return jsonify({
            'success': True,
            'drinks': drink_short
        }), 200
    except:
        abort(404)


@app.route('/drinks-detail', methods=['GET'])
@requires_auth('get:drinks-detail')
def retrieve_drinks_detail(token):
    """An endpoint to handle GET requests '/drinks-detail'
    Retrieves a list of drinks with a detailed/long description

    Arguments:
        -token: decoded jwt payload

    Returns:
        -Status code 200 and json object with
            -"success" (boolean): True or False
            -"drinks" (list): a list of drinks

    Raises:
        -404: Resource not found
    """

    drink_query = Drink.query.all()
    drink_long = [drink.long() for drink in drink_query]

    if drink_long is None:
        abort(404)

    try:
        return jsonify({
            'success': True,
            'drinks': drink_long
        }), 200
    except:
        abort(404)


@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')
def add_drink(token):
    """An endpoint to handle POST request '/drinks'
    Add a new drink to the drink table with the proper permission

    Arguments:
        -token: decoded jwt payload

    Returns:
        -Status code 200 and json object with
            -"success" (boolean): True or False
            -"drinks" (list): a list of drink

    Raises:
        -422: Unprocessable.
    """
    body = request.get_json()
    title = body.get('title', None)
    recipe = body.get('recipe', None)

    if not title or not recipe:
        return jsonify({
            "success": False,
            "error": 422,
            "message": "Title and recipe are required"
        }), 422

    try:
        drink = Drink(title=title, recipe=json.dumps(recipe))
        drink.insert()

        return jsonify({
            'success': True,
            'drinks': [drink.long()]
        }), 200

    except:
        abort(422)


@app.route('/drinks/<int:drink_id>', methods=['PATCH'])
@requires_auth('patch:drinks')
def update_drink(token, drink_id):
    """An endpoint to handle PATCH request '/drinks/<int:drink_id>'
    Update the name or recipe of the designated drinks.
    It is permitted for users who have the proper validations.

    Arguments:
        token (dict): decoded jwt payload
        drink_id (int): drink id to perform an update

    Returns:
        Status code 200 and json object with
            -"success" (boolean): True or False
            -"drinks" (list): an array containing only the updated drink

    Raises:
        -404: Resource not found
        -422: Unprocessable
    """
    body = request.get_json()
    title = body.get('title', None)
    recipe = body.get('recipe', None)

    drink = Drink.query.filter(Drink.id == drink_id).one_or_none()

    if drink is None:
        return jsonify({
            "success": False,
            "error": 404,
            "message": "No record found in the database"
        }), 404

    try:
        if title:
            drink.title = title
        if recipe:
            drink.recipe = json.dumps(recipe)

        drink.update()

        return jsonify({
            'success': True,
            'drinks': [drink.long()]
        }), 200

    except:
        return jsonify({
            "success": False,
            "error": 422,
            "message": "Title must be unique"
        }), 422


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


@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        "success": False,
        "error": 400,
        "message": "bad request"
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
