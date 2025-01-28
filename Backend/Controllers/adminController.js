const {admin} = require("../model/User_");
const bcrypt = require("bcrypt");
require('dotenv').config();
const salt1 = process.env.Salt;

//.............................login user

 // Ensure this is correctly imported

const loginAdmin = async (req, res) => {
  try {
    console.log(req.body); 
    
    const { email, password } = req.body;

    // Find the admin by email
    const user = await admin.findOne({ email: email });

    if (!user) {
      console.log("Invalid email or password");
      return res.status(400).json({
        message: "Invalid email or password",
        status: "400"
      });
    }

    // Compare entered password with the hashed password stored in the database
    const passwordMatch = bcrypt.compareSync(password, user.password);

    if (!passwordMatch) {
      console.log("Incorrect password");
      return res.status(400).json({
        message: "Incorrect password",
        status: "400"
      });
    }

    // Success - Admin found and password matches
    console.log("Admin fetched:", user.name, user.email);
    return res.status(200).json({
      status: "200",
      message: "Admin fetched successfully",
      data: user,
    });

  } catch (e) {
    console.error('Error during login:', e.message);
    return res.status(500).json({
      message: 'Server error',
      error: e.message,
    });
  }
};

module.exports = loginAdmin;

  //...............................register admin 

  // Ensure that this is correctly imported
  const saltRounds = 10; // Use a constant for salt rounds
  
  const registerAdmin = async (req, res) => {
    console.log(req.body);
    try {
      const { email, name, password } = req.body;
  
      // Check if admin already exists with the same email
      const userExist = await admin.findOne({ email: email });
      if (userExist) {
        console.log("Admin already exists with email:", email);
        return res.status(400).json({
          message: 'Admin already exists',
          status: '400',
        });
      } else {
        // Generate salt and hash password
        const salt = bcrypt.genSaltSync(saltRounds); // Generate salt
        const hashPassword = bcrypt.hashSync(password, salt);
        console.log("Hashed password:", hashPassword);
  
        // Create a new admin
        const newAdmin = new admin({
          name: name,
          email: email,
          password: hashPassword,
        });
  
        // Save the new admin to the database
        await newAdmin.save()
          .then((admindata) => {
            console.log(`Admin registered with this email: ${email}`);
            return res.status(200).json({
              status: 200,
              message: "Admin registered successfully",
              data: admindata,
            });
          })
          .catch((err) => {
            console.error('Error saving admin:', err.message);
            return res.status(500).json({
              message: "Error saving admin to database",
              error: err.message,
            });
          });
      }
    } catch (e) {
      console.error('Error during registration:', e.message);
      return res.status(500).json({
        message: "Server error",
        error: e.message,
      });
    }
  };
  
  module.exports = registerAdmin;
  

  //......................change password

  const changePassword = async (req, res) => {
    const email = req.body.email;
    
    // Fetch the user with the email and get the stored password
    const loginAdmin = await admin.findOne({ email: email });
    
    if (!loginAdmin) {
      // If the user doesn't exist, return an error
      return res.json({
        status: 400,
        message: "user not found",
      });
    }
  
    const { password: storedPassword } = loginAdmin; // Extract the stored password
    console.log("oldhash:", storedPassword);
  
    // Compare the provided old password with the stored hashed password
    const isOldPasswordCorrect = bcrypt.compareSync(req.body.old_password, storedPassword);
  
    if (!isOldPasswordCorrect) {
      // If the old password doesn't match, return an error
      console.log("wrong password");
      return res.json({
        status: 400,
        message: "wrong old password",
      });
    }
  
    const { new_password, confirm_password } = req.body;
  
    if (new_password !== confirm_password) {
      // If the new password doesn't match the confirm password, return an error
      console.log("confirm password mismatched");
      return res.json({
        status: 400,
        message: "confirm password mismatched",
      });
    }
  
    // Generate salt dynamically
    const salt = bcrypt.genSaltSync(10); // 10 rounds, adjust if needed
    
    // Hash the new password with the generated salt
    const newHash = bcrypt.hashSync(new_password, salt);
    try {
      // Update the password in the database
      await admin.updateOne({ email: email }, { password: newHash });
      console.log("user password updated");
  
      // Send success response
      return res.json({
        status: 200,
        message: "password changed",
      });
    } catch (error) {
      console.error(error.message);
      return res.json({
        status: 500,
        message: "server error",
      });
    }
  };
  
  

  //export controller
  module.exports={
    loginAdmin,registerAdmin,changePassword
  }
