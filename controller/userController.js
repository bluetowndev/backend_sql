import bcrypt from "bcrypt";
import { z } from "zod";
import jwt from "jsonwebtoken";
import prisma from "../db/db.config.js";
import { sendVerificationEmail, sendCongratulationsEmail } from "../utils/emailService.js";
import cloudinary from "cloudinary";
import axios from "axios";
import sharp from 'sharp';

const { verify, sign } = jwt;

// Configure Cloudinary
cloudinary.v2.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

const GMAP_API_KEY = process.env.GOOGLE_MAPS_API_KEY;

const createUserSchema = z.object({
    role: z.enum(["user", "admin"]).default("user"),
    email: z.string().email("Invalid email address"),
    password: z.string().min(8, "Password must be at least 8 characters long"),
    state: z.string().min(1, "State is required"),
    fullName: z.string().min(1, "Full name is required").optional(),
    phoneNumber: z.string().min(10, "Phone number must be at least 10 digits").optional(),
    reportingManager: z.string().min(1, "Reporting manager is required").optional(),
    baseLocation: z.string().min(1, "Base location is required").optional(),
    organization: z.string().min(1, "Organization is required").optional(),
    designation: z.string().min(1, "Designation is required").optional(),
    companyName: z.string().min(1, "Company name is required").optional(),
    companyPhone: z.string().min(10, "Company phone number must be at least 10 digits").optional(),
    companyAddress: z.string().min(1, "Company address is required").optional(),
    country: z.string().min(1, "Country is required").optional(),
    city: z.string().min(1, "City is required").optional(),
    zipCode: z.string().min(1, "Zip code is required").optional(),
    industry: z.string().min(1, "Industry is required").optional(),
}).superRefine((data, ctx) => {
    if (data.role === "user") {
        if (!data.fullName) ctx.addIssue({ path: ["fullName"], message: "Full name is required for users" });
        if (!data.phoneNumber) ctx.addIssue({ path: ["phoneNumber"], message: "Phone number is required for users" });
        if (!data.reportingManager) ctx.addIssue({ path: ["reportingManager"], message: "Reporting manager is required for users" });
        if (!data.baseLocation) ctx.addIssue({ path: ["baseLocation"], message: "Base location is required for users" });
        if (!data.organization) ctx.addIssue({ path: ["organization"], message: "Organization is required for users" });
    }

    if (data.role === "admin") {
        if (data.fullName) ctx.addIssue({ path: ["fullName"], message: "Full name should not be provided for admins" });
        if (data.phoneNumber) ctx.addIssue({ path: ["phoneNumber"], message: "Phone number should not be provided for admins" });
        if (data.reportingManager) ctx.addIssue({ path: ["reportingManager"], message: "Reporting manager should not be provided for admins" });
        if (data.baseLocation) ctx.addIssue({ path: ["baseLocation"], message: "Base location should not be provided for admins" });
        if (data.organization) ctx.addIssue({ path: ["organization"], message: "Organization should not be provided for admins" });
        if (!data.designation) ctx.addIssue({ path: ["designation"], message: "Designation is required for admins" });
        if (!data.companyName) ctx.addIssue({ path: ["ырcompanyName"], message: "Company name is required for admins" });
        if (!data.companyPhone) ctx.addIssue({ path: ["companyPhone"], message: "Company phone number is required for admins" });
        if (!data.companyAddress) ctx.addIssue({ path: ["companyAddress"], message: "Company address is required for admins" });
        if (!data.country) ctx.addIssue({ path: ["country"], message: "Country is required for admins" });
        if (!data.city) ctx.addIssue({ path: ["city"], message: "City is required for admins" });
        if (!data.zipCode) ctx.addIssue({ path: ["zipCode"], message: "Zip code is required for admins" });
        if (!data.industry) ctx.addIssue({ path: ["industry"], message: "Industry is required for admins" });
    }
});

export const createUser = async (req, res) => {
    try {
        const { role, ...validatedData } = createUserSchema.parse(req.body);
        const hashedPassword = await bcrypt.hash(validatedData.password, 10);

        const findUser = await prisma.user.findUnique({
            where: { email: validatedData.email },
        });

        if (findUser) {
            return res.status(400).json({
                status: 400,
                message: "Email already in use. Please use a different email!",
            });
        }

        const userData =
            role === "admin"
                ? {
                    role: "ADMIN",
                    email: validatedData.email,
                    password: hashedPassword,
                    designation: validatedData.designation,
                    companyName: validatedData.companyName,
                    companyPhone: validatedData.companyPhone,
                    companyAddress: validatedData.companyAddress,
                    country: validatedData.country,
                    state: validatedData.state,
                    city: validatedData.city,
                    zipCode: validatedData.zipCode,
                    industry: validatedData.industry,
                    fullName: "Admin User",
                    isVerified: false,
                }
                : {
                    role: "USER",
                    fullName: validatedData.fullName,
                    email: validatedData.email,
                    phoneNumber: validatedData.phoneNumber,
                    organization: validatedData.organization,
                    state: validatedData.state,
                    baseLocation: validatedData.baseLocation,
                    reportingManager: validatedData.reportingManager,
                    password: hashedPassword,
                    isVerified: false,
                };

        const newUser = await prisma.user.create({ data: userData });
        await sendVerificationEmail(newUser.email, newUser.id);

        return res.status(201).json({
            status: 201,
            message: "User created successfully! Please check your email to verify your account.",
        });
    } catch (error) {
        console.error("Error creating user:", error);
        if (error instanceof z.ZodError) {
            return res.status(400).json({
                status: 400,
                message: "Validation failed",
                errors: error.errors,
            });
        }
        if (error.code === "P2002") {
            return res.status(400).json({
                status: 400,
                message: "A unique constraint violation occurred. Please check your input.",
            });
        }
        return res.status(500).json({
            status: 500,
            message: "An unexpected error occurred while creating the user.",
        });
    }
};

export const loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await prisma.user.findUnique({ where: { email } });

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not registered, please register first",
            });
        }

        if (!user.isVerified) {
            return res.status(403).json({
                success: false,
                message: "Account not verified. Please check your email for verification link.",
            });
        }

        const isPasswordSame = await bcrypt.compare(password, user.password);
        if (!isPasswordSame) {
            return res.status(401).json({
                success: false,
                message: "Wrong password, please try again!",
            });
        }

        const accessToken = sign(
            { userId: user.id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "15m" }
        );

        const refreshToken = sign(
            { userId: user.id, name: user.fullName || "Admin User", email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        return res.status(200).json({
            success: true,
            message: "User logged in successfully!",
            user: { id: user.id, email: user.email, name: user.fullName || "Admin User", role: user.role },
            accessToken,
            refreshToken,
        });
    } catch (error) {
        console.error("Login error:", error);
        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

export const refreshToken =async (req, res) => {
    try {
        const { refreshToken } = req.body;
        if (!refreshToken) {
            return res.status(401).json({
                success: false,
                message: "Refresh token is required",
            });
        }

        const decoded = verify(refreshToken, process.env.JWT_SECRET);
        const user = await prisma.user.findUnique({ where: { id: decoded.userId } });

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Invalid refresh token",
            });
        }

        const newAccessToken = sign(
            { userId: user.id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "15m" }
        );

        return res.status(200).json({
            success: true,
            accessToken: newAccessToken,
            refreshToken,
        });
    } catch (error) {
        console.error("Refresh token error:", error);
        return res.status(401).json({
            success: false,
            message: "Invalid or expired refresh token",
        });
    }
};

export const verifyEmail = async (req, res) => {
    try {
        const { token } = req.query;
        if (!token) {
            return res.status(400).json({ status: 400, message: "Invalid or missing token" });
        }

        const decoded = verify(token, process.env.JWT_SECRET);
        const user = await prisma.user.findUnique({ where: { id: decoded.userId } });

        if (!user) {
            return res.status(400).json({ status: 400, message: "Invalid token or user does not exist" });
        }

        await prisma.user.update({
            where: { id: decoded.userId },
            data: { isVerified: true },
        });

        await sendCongratulationsEmail(user.email, user.fullName || "User");

        return res.status(200).json({
            status: 200,
            message: "Email verified successfully! Welcome aboard!",
        });
    } catch (error) {
        console.error("JWT verification error:", error.name, error.message);
        return res.status(400).json({ status: 400, message: "Invalid or expired token" });
    }
};

export const getProfile = async (req, res) => {
    try {
        const authHeader = req.headers["authorization"];
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                success: false,
                message: "Authorization token required",
            });
        }

        const token = authHeader.split(" ")[1];
        let decoded;
        try {
            decoded = verify(token, process.env.JWT_SECRET);
        } catch (error) {
            return res.status(401).json({
                success: false,
                message: "Invalid or expired token",
            });
        }

        const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found",
            });
        }

        const { password, ...userDetails } = user;
        return res.status(200).json({
            success: true,
            message: "Profile fetched successfully",
            user: userDetails,
        });
    } catch (error) {
        console.error("Error fetching profile:", error);
        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

// Reduce image size to less than 10KB
const compressImageToTargetSize = async (buffer, maxSizeInKB = 10) => {
    let quality = 100;
    let resizedBuffer = buffer;
  
    while (quality > 10) {
      const compressedBuffer = await sharp(buffer)
        .jpeg({ quality })
        .toBuffer();
  
      if (compressedBuffer.length / 1024 <= maxSizeInKB) {
        resizedBuffer = compressedBuffer;
        break;
      }
  
      quality -= 10;
    }
  
    return resizedBuffer;
  };
  
// Fetch location name from latitude and longitude
export const getLocationName = async (lat, lng) => {
  try {
      const response = await fetch(
          `https://maps.googleapis.com/maps/api/geocode/json?latlng=${lat},${lng}&result_type=street_address|premise|neighborhood|sublocality&language=en&key=${GMAP_API_KEY}`
      );
      const data = await response.json();

      if (data.status !== 'OK') {
          throw new Error(`Geocoding API error: ${data.status}`);
      }

      if (data.results.length === 0) {
          throw new Error('No location name found for the provided coordinates');
      }

      // Find the most specific result
      const preferredTypes = ['street_address', 'premise', 'point_of_interest', 'neighborhood', 'sublocality'];
      let selectedResult = data.results[0];
      let maxComponents = selectedResult.address_components.length;

      for (const result of data.results) {
          if (
              preferredTypes.some(type => result.types.includes(type)) &&
              result.address_components.length >= maxComponents
          ) {
              selectedResult = result;
              maxComponents = result.address_components.length;
          }
      }

      // Extract all relevant address components
      const addressComponents = {
          streetNumber: '',
          route: '',
          sublocality: '',
          locality: '',
          administrativeArea2: '',
          administrativeArea1: '',
          postalCode: '',
          country: '',
          premise: '',
          neighborhood: ''
      };

      for (const component of selectedResult.address_components) {
          if (component.types.includes('street_number')) {
              addressComponents.streetNumber = component.long_name;
          } else if (component.types.includes('route')) {
              addressComponents.route = component.long_name;
          } else if (component.types.includes('sublocality')) {
              addressComponents.sublocality = component.long_name;
          } else if (component.types.includes('locality')) {
              addressComponents.locality = component.long_name;
          } else if (component.types.includes('administrative_area_level_2')) {
              addressComponents.administrativeArea2 = component.long_name;
          } else if (component.types.includes('administrative_area_level_1')) {
              addressComponents.administrativeArea1 = component.long_name;
          } else if (component.types.includes('postal_code')) {
              addressComponents.postalCode = component.long_name;
          } else if (component.types.includes('country')) {
              addressComponents.country = component.long_name;
          } else if (component.types.includes('premise')) {
              addressComponents.premise = component.long_name;
          } else if (component.types.includes('neighborhood')) {
              addressComponents.neighborhood = component.long_name;
          }
      }

      // Build detailed address object
      const detailedAddress = {
          street: `${addressComponents.streetNumber} ${addressComponents.route}`.trim(),
          sublocality: addressComponents.sublocality || addressComponents.neighborhood,
          city: addressComponents.locality || addressComponents.administrativeArea2,
          state: addressComponents.administrativeArea1,
          postalCode: addressComponents.postalCode,
          country: addressComponents.country,
          premise: addressComponents.premise,
          coordinates: { lat, lng }
      };

      // Generate a formatted string for display
      const addressParts = [];
      if (detailedAddress.street) addressParts.push(detailedAddress.street);
      if (detailedAddress.premise) addressParts.push(detailedAddress.premise);
      if (detailedAddress.sublocality) addressParts.push(detailedAddress.sublocality);
      if (detailedAddress.city) addressParts.push(detailedAddress.city);
      if (detailedAddress.state) addressParts.push(detailedAddress.state);
      if (detailedAddress.postalCode) addressParts.push(detailedAddress.postalCode);
      if (detailedAddress.country) addressParts.push(detailedAddress.country);

      const formattedAddress = addressParts.join(', ');

      // Determine if the address is vague
      const isVague = !detailedAddress.street && !detailedAddress.sublocality;

      return {
          formattedAddress: formattedAddress || selectedResult.formatted_address,
          detailedAddress,
          isVague,
          coordinates: { lat, lng }
      };

  } catch (error) {
      console.error('Error fetching location name:', error.message);
      return {
          formattedAddress: `Unknown Location (${lat}, ${lng})`,
          detailedAddress: {
              street: '',
              sublocality: '',
              city: '',
              state: '',
              postalCode: '',
              country: '',
              premise: '',
              coordinates: { lat, lng }
          },
          isVague: true,
          coordinates: { lat, lng }
      };
  }
};
  
export const saveAttendance = async (req, res) => {
  try {
    // JWT Authentication
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Authorization token required',
      });
    }

    const token = authHeader.split(' ')[1];
    let decoded;
    try {
      decoded = verify(token, process.env.JWT_SECRET);
    } catch (error) {
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired token',
      });
    }

    // Extract data from request body
    const { image, location, purpose, subPurpose, feedback, timestamp, date } = req.body;

    // Validate required fields
    if (!image) {
      return res.status(400).json({ success: false, message: 'Image is required' });
    }
    if (!location) {
      return res.status(400).json({ success: false, message: 'Location is required' });
    }
    if (!purpose) {
      return res.status(400).json({ success: false, message: 'Purpose of visit is required' });
    }

    // Validate and process base64 image
    const matches = image.match(/^data:([A-Za-z-+/]+);base64,(.+)$/);
    if (!matches || matches.length !== 3) {
      return res.status(400).json({ success: false, message: 'Invalid image format' });
    }
    const buffer = Buffer.from(matches[2], 'base64');

    // Compress image
    const resizedBuffer = await compressImageToTargetSize(buffer, 10);

    // Upload to Cloudinary
    const uploadResult = await new Promise((resolve, reject) => {
      cloudinary.v2.uploader.upload_stream({ resource_type: 'image' }, (error, result) => {
        if (error) {
          console.error('Cloudinary upload error:', error);
          reject(new Error('Cloudinary upload failed'));
        } else {
          resolve(result);
        }
      }).end(resizedBuffer);
    });

    // Parse location
    let parsedLocation;
    try {
      parsedLocation = JSON.parse(location);
      if (!parsedLocation.lat || !parsedLocation.lng) {
        throw new Error('Invalid location format');
      }
    } catch (error) {
      return res.status(400).json({ success: false, message: 'Invalid location format' });
    }

    // Get detailed location information
    const locationInfo = await getLocationName(parsedLocation.lat, parsedLocation.lng);
    
    // Prepare address data for storage
    const addressData = {
      formattedAddress: locationInfo.formattedAddress,
      street: locationInfo.detailedAddress.street,
      sublocality: locationInfo.detailedAddress.sublocality,
      city: locationInfo.detailedAddress.city,
      state: locationInfo.detailedAddress.state,
      postalCode: locationInfo.detailedAddress.postalCode,
      country: locationInfo.detailedAddress.country,
      premise: locationInfo.detailedAddress.premise,
      isVague: locationInfo.isVague,
      coordinates: locationInfo.coordinates
    };

    // Prepare attendance data
    const attendanceTimestamp = timestamp ? new Date(timestamp) : new Date();
    const attendanceDate = date || attendanceTimestamp.toISOString().split('T')[0];

    // Save to Prisma database
    const attendance = await prisma.attendance.create({
      data: {
        image: uploadResult.secure_url,
        lat: parsedLocation.lat,
        lng: parsedLocation.lng,
        locationName: addressData.formattedAddress,
        // locationDetails: addressData, // Store all address details as JSON
        purpose,
        subPurpose: subPurpose || null,
        feedback: feedback || null,
        timestamp: attendanceTimestamp,
        date: attendanceDate,
        userId: decoded.userId,
      },
    });

    return res.status(201).json({
      success: true,
      message: 'Attendance saved successfully',
      data: {
        ...attendance,
        // locationDetails: addressData // Include in response
      },
    });
  } catch (error) {
    console.error('Error saving attendance:', error);
    return res.status(500).json({
      success: false,
      message: 'Error processing attendance',
      error: error.message,
    });
  }
};

// Get attendance records for the logged-in user
export const getAttendanceRecords = async (req, res) => {
    try {
        // JWT Authentication
        const authHeader = req.headers["authorization"];
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                success: false,
                message: "Authorization token required",
            });
        }

        const token = authHeader.split(" ")[1];
        let decoded;
        try {
            decoded = verify(token, process.env.JWT_SECRET);
        } catch (error) {
            return res.status(401).json({
                success: false,
                message: "Invalid or expired token",
            });
        }

        const attendanceRecords = await prisma.attendance.findMany({
            where: {
                userId: decoded.userId,
            },
            select: {
                id: true,
                date: true,
                timestamp: true,
                purpose: true,
                subPurpose: true,
                locationName: true,
                lat: true,
                lng: true,
                feedback: true,
                image: true,
                createdAt: true,
            },
            orderBy: {
                timestamp: 'desc',
            },
        });

        // Transform the data to ensure proper formatting
        const formattedRecords = attendanceRecords.map(record => ({
            id: record.id,
            date: record.date,
            timestamp: record.timestamp.toISOString(),
            purpose: record.purpose,
            subPurpose: record.subPurpose || null,
            locationName: record.locationName,
            lat: record.lat,
            lng: record.lng,
            feedback: record.feedback || null,
            image: record.image,
            createdAt: record.createdAt.toISOString(),
        }));

        return res.status(200).json({
            success: true,
            message: "Attendance records fetched successfully",
            data: formattedRecords,
        });
    } catch (error) {
        console.error("Error fetching attendance records:", error);
        return res.status(500).json({
            success: false,
            message: "Internal server error",
            error: error.message,
        });
    }
};