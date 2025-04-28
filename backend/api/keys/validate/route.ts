// Check if key is expired
if (new Date() > new Date(keyDoc.expiresAt)) {
  // Update the key status to expired
  await Key.updateOne(
    { _id: keyDoc._id },
    { $set: { status: 'expired' } }
  );
  
  return NextResponse.json(
    { 
      success: false, 
      message: 'This key has expired' 
    }, 
    { status: 400 }
  );
} 
