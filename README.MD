# Jobs-API

## Overview
* This repository contains a Job API built using Node.js and Express. The API provides endpoints for creating, reading, updating, and deleting job postings and user authentication for logging in and registering users. It is designed to be scalable, efficient, and easy to integrate with front-end applications.

## Features
- Create Job Postings: Add new job listings with details such as title, description, company, location, and salary.
- Read Job Postings: Retrieve a list of all job postings or fetch details of a specific job by its ID.
- Update Job Postings: Modify existing job postings to keep the information up to date.
- Delete Job Postings: Remove job postings that are no longer relevant.
- Search Functionality: Search for job postings based on keywords, location, or company.
- Pagination: Efficiently handle large sets of job postings with pagination.
- User Registration: Allow new users to register by providing a username and password.
- User Login: Authenticate users and provide them with a JSON Web Token (JWT) for accessing protected routes.

## Technologies Used
- Node.js: JavaScript runtime for server-side development.
- Express Fast, unopinionated, minimalist web framework for Node.js.
- MongoDB: NoSQL database for storing job postings and user information.
- Mongoose: Elegant MongoDB object modeling for Node.js.
- JWT: JSON Web Tokens for securing user authentication.

## Installation
- Clone the repository: git clone https://github.com/Elkady-Code/Jobs-API
- Navigate to the project directory:
- cd job-api
- Install dependencies: npm install
- Set up environment variables (create a .env file in the root directory):
* PORT= `3000`
* MONGO_URI=`your_mongodb_connection_string`
* JWT_SECRET=`your_jwt_secret`
- Start the server: npm start

## Usage
After starting the server, you can use tools like Postman or cURL to interact with the API endpoints.

- User Authentication <br>
POST /api/v1/auth/register: Register a new user. <br>
POST /api/v1/auth/login: Log in a user and receive a JWT.
- Job Postings <br>
GET /api/v1/jobs: Retrieve all job postings. <br>
GET /api/v1/jobs/: Retrieve a specific job posting by ID. <br>
POST /api/v1/jobs: Create a new job posting (protected route). <br>
PUT /api/v1/jobs/ : Update an existing job posting by ID (protected route). <br>
DELETE /api/v1/jobs/ : Delete a job posting by ID (protected route).

## API-Testing-Result
- User Registration: ![User-Registration](https://github.com/user-attachments/assets/740df2eb-fe22-4664-ab8c-b69e60fc7eca)
- User Login: ![Login](https://github.com/user-attachments/assets/4c448f33-cf28-494d-ab5b-b12764f196a4)
- Creating a job: ![CreateJob](https://github.com/user-attachments/assets/011e5e9b-edc2-4f2e-97ed-b9eedf04542d)
- Get all jobs: ![GetAllJobs](https://github.com/user-attachments/assets/84e2d964-16de-4a4c-b684-2f9c698dfa31)

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## License
This project is licensed under the MIT License.
