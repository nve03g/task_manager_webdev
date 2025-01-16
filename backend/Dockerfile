# Use an official Node.js runtime as the base image
FROM node:18

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy only package.json and package-lock.json to the container
COPY package.json package-lock.json ./

# Install dependencies
RUN npm install

# Rebuild native modules (e.g., sqlite3) for the container's architecture
RUN npm rebuild sqlite3

# Rebuild native modules (if any)
RUN npm rebuild

# Copy the rest of the application files
COPY . .

# Expose the port the app runs on
EXPOSE 443

# Command to start the app
CMD ["node", "server.js"]
