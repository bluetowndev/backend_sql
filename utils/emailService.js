import nodemailer from "nodemailer";
import jwt from 'jsonwebtoken';

const { sign } = jwt;

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Function to send a verification email
export const sendVerificationEmail = async (email, userId) => {
  try {
    const token = sign({ userId }, process.env.JWT_SECRET, { expiresIn: "1h" });

    const verificationLink = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Verify Your Email - WorkTrack",
      html: `
          <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
            <div style="background: #f8f9fa; padding: 30px; border-radius: 10px; text-align: center;">
              <h1 style="color: #2c3e50; margin-bottom: 25px;">Verify Your Email Address</h1>
              
              <p style="margin-bottom: 30px; line-height: 1.6;">
                Thank you for signing up! To complete your registration, please verify your email address by clicking the button below:
              </p>
              
              <a href="${verificationLink}" 
                 style="display: inline-block; 
                        padding: 12px 30px; 
                        background: #4a6bff; 
                        color: white; 
                        text-decoration: none; 
                        border-radius: 30px; 
                        font-weight: 500; 
                        font-size: 16px;
                        box-shadow: 0 3px 10px rgba(74, 107, 255, 0.3);
                        transition: all 0.3s ease;">
                Verify Email Address
              </a>
              
              <p style="margin-top: 30px; color: #777; font-size: 14px;">
                For your security, this link will expire in <strong>1 hour</strong>.<br>
                If you didn't request this, please ignore this email.
              </p>
            </div>
            
            <div style="text-align: center; margin-top: 20px; color: #999; font-size: 12px;">
              <p>© ${new Date().getFullYear()} WorkTrack. All rights reserved.</p>
            </div>
          </div>
        `,
    };

    await transporter.sendMail(mailOptions);
    console.log(`Verification email sent to ${email}`);
  } catch (error) {
    console.error("Error sending verification email:", error);
    throw error; // Re-throw the error so it can be handled by the caller
  }
};

// Function to send a congratulations email
export const sendCongratulationsEmail = async (email, name) => {
  try {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Welcome to WorkTrack - Account Successfully Set Up!",
      html: `
          <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
            <div style="background: #f8f9fa; padding: 30px; border-radius: 10px; text-align: center;">
              <h1 style="color: #2c3e50; margin-bottom: 25px;">Welcome, ${name}!</h1>
              
              <p style="margin-bottom: 20px; line-height: 1.6;">
                Congratulations! Your WorkTrack account has been successfully set up and verified.
              </p>
              
              <p style="margin-bottom: 30px; line-height: 1.6;">
                You're now ready to start tracking your work and boosting productivity. Get started by:
              </p>
              
              <div style="text-align: left; max-width: 400px; margin: 0 auto 30px;">
                <ul style="list-style: none; padding: 0;">
                  <li style="margin-bottom: 15px;">✅ Setting up your profile</li>
                  <li style="margin-bottom: 15px;">✅ Exploring dashboard features</li>
                  <li style="margin-bottom: 15px;">✅ Adding your first task</li>
                </ul>
              </div>
              
              <a href="${process.env.FRONTEND_URL}" 
                 style="display: inline-block; 
                        padding: 12px 30px; 
                        background: #4a6bff; 
                        color: white; 
                        text-decoration: none; 
                        border-radius: 30px; 
                        font-weight: 500; 
                        font-size: 16px;
                        box-shadow: 0 3px 10px rgba(74, 107, 255, 0.3);
                        transition: all 0.3s ease;">
                Get Started Now
              </a>
              
              <p style="margin-top: 30px; color: #777; font-size: 14px;">
                Need help? Contact our support team at <a href="mailto:support@worktrack.com">support@worktrack.com</a>
              </p>
            </div>
            
            <div style="text-align: center; margin-top: 20px; color: #999; font-size: 12px;">
              <p>© ${new Date().getFullYear()} WorkTrack. All rights reserved.</p>
            </div>
          </div>
        `,
    };

    await transporter.sendMail(mailOptions);
    console.log(`Congratulations email sent to ${email}`);
  } catch (error) {
    console.error("Error sending congratulations email:", error);
    throw error; // Re-throw the error so it can be handled by the caller
  }
};