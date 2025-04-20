from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# This is a simple example of a route.  When you go to http://localhost:5000/
# in your browser, it will render the index.html template.
@app.route('/')
def index():
    return render_template('index.html')  # Make sure you have an index.html in a 'templates' folder

# This is a POST endpoint that you can call from your HTML using JavaScript.
# It expects JSON data with a 'name' field.  It will return a JSON response
# with a 'message' field.
@app.route('/api/greet', methods=['POST'])
def greet():
    data = request.get_json()
    if not data or 'name' not in data:
        return jsonify({'error': 'Name is required'}), 400  #  Return a 400 Bad Request error

    name = data['name']
    message = f'Hello, {name}!'
    return jsonify({'message': message})
# This is another example of a POST endpoint, demonstrating how to handle
# different data types and return different HTTP status codes.
@app.route('/api/process', methods=['POST'])
def process_data():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    try:
        value = data['value']
        #  Example of handling different data types.
        if isinstance(value, int):
            result = value * 2
            return jsonify({'result': result, 'message': 'Integer processed'}), 200
        elif isinstance(value, str):
            result = value.upper()
            return jsonify({'result': result, 'message': 'String processed'}), 200
        else:
            return jsonify({'error': 'Unsupported data type'}), 400
    except KeyError:
        return jsonify({'error': 'Key "value" not found'}), 400
    except Exception as e:
        #  Important:  Log the error for debugging.
        print(f"Error processing data: {e}")
        return jsonify({'error': 'Internal server error'}), 500  #  Return 500 for server errors

#  Example of a GET endpoint.  This one takes a parameter from the URL.
@app.route('/api/items/<int:item_id>', methods=['GET'])
def get_item(item_id):
    #  In a real application, you would probably fetch data from a database here.
    #  For this example, we'll just return a mock response.
    if item_id == 123:
        return jsonify({'id': item_id, 'name': 'Example Item', 'description': 'This is an example item.'}), 200
    else:
        return jsonify({'error': 'Item not found'}), 404  #  Return 404 if the item is not found.

# curl -X POST http://localhost:5000/api/items \
"Content-Type: application/json" 
{"name": "New Item",
  "description": "This is a new item."
  ""}
# Example of a POST endpoint to add a new item.
@app.route('/api/items', methods=['POST'])
def add_item():
    data = request.get_json()
    if not data or 'name' not in data or 'description' not in data:
        return jsonify({'error': 'Name and description are required'}), 400

    item = {
        "name": data['name'],
        "description": data['description']
    }
    return jsonify({
        "message": "Item added successfully",
        "item": item
    }), 201

if __name__ == '__main__':
    app.run(debug=True) #  Don't use debug=True in production.  It's for development only!

# curl -X POST http://localhost:5000/api/items \
"Content-Type: application/json" 
'{"name": "New Item", "description": "This is a new item."}'