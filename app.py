from flask import Blueprint, jsonify, request
from . import db
from .models import User

main = Blueprint('main', __name__)

@main.route('/user', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify(
        [
            {"id": user.id,
            "nama": user.nama,
            "email": user.email
            }
            for user in users
        ]
    )

@main.route('/user/<int:id>', methods=['GET'])
def get_user(id):
    user = User.query.get(id)
    if user:
        return jsonify(
            [
                {"id": user.id,
                "nama": user.nama,
                "email": user.email
                }
                for user in user
            ]
        )
    return jsonify({"message": "Tidak Ada"}), 404

@main.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()
    nama = data.get('nama')
    email = data.get('email')

    if not nama or not email:
        return jsonify({"message": "Data harus diisi"}), 404
    
    new_user = User(nama=nama, email=email)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User berhasil ditambahkan", "user": {"id": new_user.id, "nama": new_user.nama, "email": new_user.email}}), 201
    
@main.route('/user/<int:id>', methods=['PUT'])
def update_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({"message": "User tidak ditemukan"}), 404
    
    data = request.get_json()
    user.nama = data.get('nama', user.nama)
    user.email = data.get('email', user.email)

    return jsonify({"message": "User telah terupdate", "user": {"id": user.id, "nama": user.nama, "email": user.email}}), 200

@main.route('/user/<int:id>', methods=['DELETE'])
def delete_user(id):
    user = User.query.get(id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted successfully'}), 200
    else:
        return jsonify({'message': 'User not found'}), 404
