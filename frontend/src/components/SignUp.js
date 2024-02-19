import React from 'react';
import { useForm } from 'react-hook-form';
import toast from 'react-hot-toast';
import { Link, useNavigate } from 'react-router-dom';

const SignUp = () => {
    const { register, handleSubmit, formState: { errors } } = useForm();
    let navigate = useNavigate()

    const onSubmit = async (data) => {
        try {
            const response = await fetch('http://localhost:9000/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            });

            if (response.ok) {
                toast.success('Login successful!');

                navigate('/login')
                // Redirect to login page or show a success message
            } else {
                toast.error('Error during registration');

                console.error('Registration failed:');
                // Handle error: show error message to the user or retry registration
            }
        } catch (error) {
            toast.error('Error during registration');

            console.error('Error during registration:', error);
            // Handle error: show error message to the user or retry registration
        }
    };

    return (
        <div>
            <form onSubmit={handleSubmit(onSubmit)} className="mx-auto max-w-md p-6 bg-white shadow-md rounded-md">
                <h2 className="text-2xl font-semibold mb-4 text-center">Register</h2>
                <div className="mb-4">
                    <label htmlFor="username" className="block text-gray-700">Username</label>
                    <input {...register('username', { required: true })} type="text" id="username" name="username" className="mt-1 p-2 border rounded-md w-full focus:outline-none focus:ring focus:border-blue-300" />
                    {errors.username && <span className="text-red-500">Username is required</span>}
                </div>
                <div className="mb-4">
                    <label htmlFor="email" className="block text-gray-700">Email</label>
                    <input {...register('email', {
                        required: "Email is required",
                        pattern: {
                            value: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
                            message: "Invalid email address"
                        }
                    })} type="email" id="email" name="email" className="mt-1 p-2 border rounded-md w-full focus:outline-none focus:ring focus:border-blue-300" />
                    {errors.email && <span className="text-red-500">{errors.email.message}</span>}
                </div>
                <div className="mb-4">
                    <label htmlFor="password" className="block text-gray-700">Password</label>
                    <input {...register('password', { required: "Password is required", minLength: { value: 6, message: "Password must be at least 6 characters long" } })} type="password" id="password" name="password" className="mt-1 p-2 border rounded-md w-full focus:outline-none focus:ring focus:border-blue-300" />
                    {errors.password && <span className="text-red-500">{errors.password.message}</span>}
                </div>
                <div className="mb-4">
                    <label htmlFor="role" className="block text-gray-700">Role</label>
                    <select {...register('role')} id="role" name="role" className="mt-1 p-2 border rounded-md w-full focus:outline-none focus:ring focus:border-blue-300">
                        <option value="admin">Admin</option>
                        <option value="member">Member</option>
                        <option value="guest">Guest</option>
                    </select>
                </div>
                <button type="submit" className="bg-blue-500 text-white px-4 py-2 rounded-md hover:bg-blue-600 w-full">Submit</button>
                <div className="mt-4 text-gray-600">
                    Already have an account? <Link to="/login" className="text-blue-500">Log in here</Link>
                </div>
            </form>
        </div>
    );
}

export default SignUp;
