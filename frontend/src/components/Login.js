import axios from 'axios';
import Cookies from 'js-cookie';
import React from 'react'
import { useForm } from 'react-hook-form';
import { Link, useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast'


const Login = () => {

    const { register, handleSubmit, formState: { errors } } = useForm();

    let navigate = useNavigate()

    const onSubmit = async (data) => {
        try {
            const response = await axios.post('http://localhost:9000/login', data);

            if (response.status === 200) {
                const token = response.data.token;
                toast.success('Login successful!');

                Cookies.set('token', token); // Set the token into a cookie

                navigate('/');
                // Redirect to home page or wherever you want
            } else {
                toast.error('Login failed!')
                // Handle error: show error message to the user or retry login
            }
        } catch (error) {
            toast.error(error.response.data)

            console.error('Error during login:', error.response.data);
            // Handle error: show error message to the user or retry login
        }
    };


    return (
        <div>
            <form onSubmit={handleSubmit(onSubmit)} className="mx-auto max-w-md p-6 bg-white shadow-md rounded-md">
                <h2 className="text-2xl font-semibold mb-4 text-center">Login</h2>
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
                <button type="submit" className="bg-blue-500 text-white px-4 py-2 rounded-md hover:bg-blue-600 w-full">Submit</button>
                <div className="mt-4 text-gray-600">
                    Don't have an account? <Link to="/signup" className="text-blue-500">Sign up here</Link>
                </div>
            </form>

        </div>
    )
}

export default Login
